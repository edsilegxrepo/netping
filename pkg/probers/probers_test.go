package probers

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/consts"
	"github.com/edsilegx/netping/pkg/stats"
	"github.com/stretchr/testify/assert"
)

func startTCPTestServer(t *testing.T) (net.Listener, uint16) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	return ln, uint16(p)
}

func TestTcping(t *testing.T) {
	ln, port := startTCPTestServer(t)
	defer ln.Close()

	opts := TCPOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    port,
		Timeout: 2 * time.Second,
	}

	tcp := NewTcping(opts)
	res := tcp.Ping(context.Background())

	assert.NoError(t, res.Err)
	assert.NotNil(t, res.LocalAddr)
	assert.True(t, res.RTT >= 0)
}

func TestHTTPing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	addrParts := strings.Split(strings.TrimPrefix(ts.URL, "http://"), ":")
	portNum, _ := strconv.Atoi(addrParts[1])

	opts := HTTPOptions{
		Hostname: addrParts[0],
		IP:       netip.MustParseAddr(addrParts[0]),
		Port:     uint16(portNum),
		Protocol: consts.HTTP,
		Timeout:  2 * time.Second,
	}

	h := NewHTTPing(opts)
	res := h.Ping(context.Background())

	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusOK, res.HTTPStatus)
}

func TestUDPing(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer pc.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()

	addrParts := strings.Split(pc.LocalAddr().String(), ":")
	portNum, _ := strconv.Atoi(addrParts[1])

	opts := UDPOptions{
		IP:         netip.MustParseAddr("127.0.0.1"),
		Port:       uint16(portNum),
		Timeout:    1 * time.Second,
		SendData:   "PING",
		ExpectData: "PING",
	}

	u := NewUDPing(opts)
	res := u.Ping(context.Background())

	assert.NoError(t, res.Err)
}

func TestWSing(t *testing.T) {
	// Simple mock WebSocket server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				var secKey string
				for {
					line, err := reader.ReadString('\n')
					if err != nil || strings.TrimSpace(line) == "" {
						break
					}
					if strings.HasPrefix(strings.ToLower(line), "sec-websocket-key:") {
						secKey = strings.TrimSpace(line[18:])
					}
				}

				h := sha1.New()
				h.Write([]byte(secKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

				resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acceptKey)
				_, _ = c.Write([]byte(resp))

				// Read frame
				buf := make([]byte, 10)
				_, _ = c.Read(buf)
				// Send Pong frame (0x8a, len 0)
				_, _ = c.Write([]byte{0x8a, 0x00})
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	ws := NewWSing(WSOptions{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		UseTLS:   false,
		Timeout:  2 * time.Second,
	})

	res := ws.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, 101, res.HTTPStatus)
}

func TestDNSQueryProber(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer pc.Close()

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			// Echo DNS reply with standard response flags (0x8180)
			resp := make([]byte, n)
			copy(resp, buf[:n])
			if len(resp) >= 4 {
				resp[2] = 0x81
				resp[3] = 0x80 // NOERROR
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()

	parts := strings.Split(pc.LocalAddr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	dp := NewDNSQueryProber(DNSQueryOptions{
		Nameserver: "127.0.0.1",
		IP:         netip.MustParseAddr("127.0.0.1"),
		Port:       uint16(portNum),
		Domain:     "example.com",
		IsDoH:      false,
		Timeout:    2 * time.Second,
	})

	res := dp.Ping(context.Background())
	assert.NoError(t, res.Err)
}

func TestRedising(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						break
					}
					if strings.Contains(line, "PING") {
						c.Write([]byte("+PONG\r\n"))
					} else if strings.Contains(line, "INFO") {
						infoData := "redis_version:7.2.4\r\nrole:master\r\nconnected_clients:3\r\nused_memory_human:14.2M\r\n"
						c.Write([]byte(fmt.Sprintf("$%d\r\n%s\r\n", len(infoData), infoData)))
						break
					}
				}
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	red := NewRedising(RedisOptions{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := red.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "7.2.4")
	assert.Contains(t, res.Diagnostics, "master")
	assert.Contains(t, res.Diagnostics, "14.2M")
}

func TestSSHing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	ssh := NewSSHing(SSHOptions{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := ssh.Ping(context.Background())
	assert.NoError(t, res.Err)
}

func TestDBing_Postgres(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 8)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("S")) // SSL supported
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	pg := NewDBing(DBOptions{
		Type:     PostgreSQL,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := pg.Ping(context.Background())
	assert.NoError(t, res.Err)
}

func TestDBing_MySQL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// MySQL HandshakeV10: proto 0x0a, version "8.0.36\0", thread_id 1
				payload := append([]byte{0x0a}, append([]byte("8.0.36\x00"), make([]byte, 24)...)...)
				hdr := []byte{byte(len(payload)), 0x00, 0x00, 0x00}
				_, _ = c.Write(append(hdr, payload...))
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	mysql := NewDBing(DBOptions{
		Type:     MySQL,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := mysql.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "8.0.36")
}

func TestDBing_MSSQL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				// TDS PRELOGIN response: 8-byte header + option table + payload
				// Option 0: VERSION (offset 11, len 6), Option 1: ENCRYPTION (offset 17, len 1), Terminator 0xFF
				body := []byte{
					0x00, 0x00, 0x0b, 0x00, 0x06, // Option 0: VERSION offset 11, len 6
					0x01, 0x00, 0x11, 0x00, 0x01, // Option 1: ENCRYPTION offset 17, len 1
					0xff,                         // Terminator
					0x10, 0x00, 0x10, 0x13, 0x00, 0x01, // Version payload: 16.0.4115.1 (SQL Server 2022)
					0x01, // Encryption: ENCRYPT_ON (1)
				}
				totLen := uint16(8 + len(body))
				hdr := []byte{0x04, 0x01, byte(totLen >> 8), byte(totLen), 0x00, 0x00, 0x00, 0x00}
				_, _ = c.Write(append(hdr, body...))
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	mssql := NewDBing(DBOptions{
		Type:     MSSQL,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := mssql.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "SQL Server 2022")
}

func TestDBing_Oracle(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				_, _ = c.Read(buf)
				// TNS REFUSE packet: 8-byte header (type 0x04) + error string with VSN and ERR
				refuseBody := []byte("(DESCRIPTION=(TMP=)(VSN=318767104)(ERR=12514)(ERROR_STACK=(ERROR=(CODE=12514))))")
				totLen := uint16(8 + len(refuseBody))
				hdr := []byte{byte(totLen >> 8), byte(totLen), 0x00, 0x00, 0x04, 0x00, 0x00, 0x00}
				_, _ = c.Write(append(hdr, refuseBody...))
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	ora := NewDBing(DBOptions{
		Type:     Oracle,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := ora.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "Oracle 19c")
	assert.Contains(t, res.Diagnostics, "TNS-12514")
}

func TestDBing_MongoDB(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 128)
				_, _ = c.Read(buf)
				// OP_MSG response: 16-byte header + 4-byte flags + 1-byte kind + BSON doc
				bsonDoc := append([]byte{0x02}, append([]byte("version\x00\x06\x00\x00\x007.0.5\x00"), 0x00)...)
				docLen := uint32(len(bsonDoc) + 4)
				fullDoc := append([]byte{byte(docLen), 0x00, 0x00, 0x00}, bsonDoc...)
				body := append([]byte{0x00, 0x00, 0x00, 0x00, 0x00}, fullDoc...) // flags (4) + kind (1) + doc
				totLen := uint32(16 + len(body))
				hdr := []byte{byte(totLen), 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xdd, 0x07, 0x00, 0x00}
				_, _ = c.Write(append(hdr, body...))
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	mongo := NewDBing(DBOptions{
		Type:     MongoDB,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := mongo.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "7.0.5")
}

func TestDBing_Cassandra(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte{0x84, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00}) // CQL READY
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	cql := NewDBing(DBOptions{
		Type:     Cassandra,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := cql.Ping(context.Background())
	assert.NoError(t, res.Err)
}

func TestDBing_SAPHANA(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				_, _ = c.Read(buf) // 8-byte init
				// 8-byte init response (Major 4 Minor 1)
				_, _ = c.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00})
				// Read authenticate request
				_, _ = c.Read(buf)
				// Write authentication response containing version, SYSTEMDB, SCRAMSHA256
				resp := []byte("...2.00.070.00.1679647833...SYSTEMDB...SCRAMSHA256...PASSWORD...")
				msgHdr := make([]byte, 36)
				_, _ = c.Write(append(msgHdr, resp...))
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	hana := NewDBing(DBOptions{
		Type:     SAPHANA,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := hana.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "SAP HANA 2.0 SPS07")
	assert.Contains(t, res.Diagnostics, "SYSTEMDB")
	assert.Contains(t, res.Diagnostics, "SCRAMSHA256")
}

func TestMemcacheding(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						break
					}
					lineTrim := strings.TrimSpace(line)
					if lineTrim == "version" {
						c.Write([]byte("VERSION 1.6.22\r\n"))
					} else if lineTrim == "stats" {
						c.Write([]byte("STAT curr_connections 4\r\nSTAT curr_items 1500\r\nSTAT bytes 10485760\r\nSTAT limit_maxbytes 67108864\r\nSTAT get_hits 950\r\nSTAT get_misses 50\r\nSTAT uptime 86400\r\nEND\r\n"))
						break
					}
				}
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	mem := NewMemcacheding(MemcachedOptions{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := mem.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "1.6.22")
	assert.Contains(t, res.Diagnostics, "Conns: 4")
	assert.Contains(t, res.Diagnostics, "Items: 1500")
	assert.Contains(t, res.Diagnostics, "HitRatio: 95.0%")
}

func TestMailing_SMTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("220 mail.example.com ESMTP\r\n"))
				reader := bufio.NewReader(c)
				_, _ = reader.ReadString('\n')
				_, _ = c.Write([]byte("250-mail.example.com\r\n250 HELP\r\n"))
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	smtp := NewMailing(MailOptions{
		Protocol: MailSMTP,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := smtp.Ping(context.Background())
	assert.NoError(t, res.Err)
}

func TestMailing_IMAP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("* OK IMAP4rev1 Server Ready\r\n"))
				reader := bufio.NewReader(c)
				_, _ = reader.ReadString('\n')
				_, _ = c.Write([]byte("* CAPABILITY IMAP4rev1 STARTTLS\r\nA001 OK CAPABILITY completed\r\n"))
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	imap := NewMailing(MailOptions{
		Protocol: MailIMAP,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := imap.Ping(context.Background())
	assert.NoError(t, res.Err)
}

func TestLDAPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32)
				_, _ = c.Read(buf)
				// LDAP BindResponse ASN.1 sequence
				_, _ = c.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	ldap := NewLDAPing(LDAPOptions{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		UseTLS:   false,
		Timeout:  2 * time.Second,
	})

	res := ldap.Ping(context.Background())
	assert.NoError(t, res.Err)
}

func TestMailing_POP3(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("+OK POP3 server ready\r\n"))
				reader := bufio.NewReader(c)
				_, _ = reader.ReadString('\n')
				_, _ = c.Write([]byte("+OK NOOP completed\r\n"))
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	pop3 := NewMailing(MailOptions{
		Protocol: MailPOP3,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := pop3.Ping(context.Background())
	assert.NoError(t, res.Err)
}

func TestTLSing(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	addrParts := strings.Split(strings.TrimPrefix(ts.URL, "https://"), ":")
	portNum, _ := strconv.Atoi(addrParts[1])

	tlsProber := NewTLSing(TLSOptions{
		Hostname:   addrParts[0],
		IP:         netip.MustParseAddr(addrParts[0]),
		Port:       uint16(portNum),
		Timeout:    2 * time.Second,
		SkipVerify: true,
	})

	res := tlsProber.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.NotZero(t, res.TLSTime)
}

func TestO365ing(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("request-id", "mock-uuid-1234")
		w.Header().Set("x-ms-ags-diagnostic", `{"ServerInfo":{"DataCenter":"East US"}}`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"autodiscover":{"response":{"protocol":{"type":"EXPR"}}}}`))
	}))
	defer ts.Close()

	addrParts := strings.Split(strings.TrimPrefix(ts.URL, "https://"), ":")
	portNum, _ := strconv.Atoi(addrParts[1])

	o365Prober := NewO365ing(O365Options{
		Hostname:   addrParts[0],
		IP:         netip.MustParseAddr(addrParts[0]),
		Port:       uint16(portNum),
		SkipVerify: true,
		Timeout:    2 * time.Second,
	})
	// Force URL to mock server URL
	o365Prober.url = ts.URL

	res := o365Prober.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusOK, res.HTTPStatus)
}

func TestStorageing(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-amz-request-id", "TX123456789")
		w.Header().Set("x-ms-request-id", "blob-123456789")
		w.Header().Set("x-goog-generation", "1700000000")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	addrParts := strings.Split(strings.TrimPrefix(ts.URL, "https://"), ":")
	portNum, _ := strconv.Atoi(addrParts[1])

	// S3
	s3Prober := NewStorageing(StorageOptions{
		Type:       StorageS3,
		Hostname:   addrParts[0],
		IP:         netip.MustParseAddr(addrParts[0]),
		Port:       uint16(portNum),
		SkipVerify: true,
		Timeout:    2 * time.Second,
	})
	s3Prober.url = ts.URL
	res := s3Prober.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusOK, res.HTTPStatus)

	// Azure Blob
	blobProber := NewStorageing(StorageOptions{
		Type:       StorageAzureBlob,
		Hostname:   addrParts[0],
		IP:         netip.MustParseAddr(addrParts[0]),
		Port:       uint16(portNum),
		SkipVerify: true,
		Timeout:    2 * time.Second,
	})
	blobProber.url = ts.URL
	res = blobProber.Ping(context.Background())
	assert.NoError(t, res.Err)

	// GCS
	gcsProber := NewStorageing(StorageOptions{
		Type:       StorageGCS,
		Hostname:   addrParts[0],
		IP:         netip.MustParseAddr(addrParts[0]),
		Port:       uint16(portNum),
		SkipVerify: true,
		Timeout:    2 * time.Second,
	})
	gcsProber.url = ts.URL
	res = gcsProber.Ping(context.Background())
	assert.NoError(t, res.Err)
}

func TestQueueing_Kafka(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32)
				_, _ = c.Read(buf)
				// Response: 4 bytes length (8), 4 bytes correlation ID (1), 2 bytes error code (0)
				_, _ = c.Write([]byte{0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00})
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	kafkaProber := NewQueueing(QueueOptions{
		Protocol: QueueKafka,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := kafkaProber.Ping(context.Background())
	assert.NoError(t, res.Err)
}

func TestQueueing_RabbitMQ(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 8)
				_, _ = c.Read(buf)
				// Response: AMQP 0-9-1 Connection.Start Method frame (starts with 0x01)
				_, _ = c.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00})
			}(conn)
		}
	}()

	parts := strings.Split(ln.Addr().String(), ":")
	portNum, _ := strconv.Atoi(parts[len(parts)-1])

	rmqProber := NewQueueing(QueueOptions{
		Protocol: QueueRabbitMQ,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := rmqProber.Ping(context.Background())
	assert.NoError(t, res.Err)
}

type mockFlakyPinger struct {
	attempts int
}

func (m *mockFlakyPinger) Ping(ctx context.Context) ProbeResult {
	m.attempts++
	if m.attempts < 3 {
		return ProbeResult{
			RTT: 5 * time.Millisecond,
			Err: errors.New("temporary connection reset"),
		}
	}
	return ProbeResult{
		RTT: 10 * time.Millisecond,
		Err: nil,
	}
}

func TestProber_RetryWithExponentialBackoff(t *testing.T) {
	flaky := &mockFlakyPinger{}
	st := stats.NewStatistics(stats.Options{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     80,
	})

	prober := NewProber(flaky, nil, st, Options{
		Timeout:               500 * time.Millisecond,
		IntervalBetweenProbes: 10 * time.Millisecond,
		ProbesBeforeQuit:      1,
		Retries:               3,
		InitialRetryBackoff:   5 * time.Millisecond,
		MaxRetryBackoff:       50 * time.Millisecond,
		RetryJitter:           false,
	})

	resStats, err := prober.Probe(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, uint(1), resStats.TotalSuccessfulProbes)
	assert.Equal(t, uint(0), resStats.TotalUnsuccessfulProbes)
	assert.Equal(t, 3, flaky.attempts)
}

func TestSMBing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil || n < 68 {
			return
		}

		// Verify client sent SMB 3.1.1 Negotiate Request
		if buf[4] != 0xfe || buf[5] != 'S' || buf[6] != 'M' || buf[7] != 'B' {
			return
		}

		// Build a mock SMB2 Negotiate Response (Dialect 0x0311, Signing Enabled, DFS|Encryption)
		respBody := make([]byte, 200)
		// SMB2 Header (64 bytes)
		copy(respBody[0:4], []byte{0xfe, 'S', 'M', 'B'})
		respBody[4] = 0x40 // StructureSize = 64
		// Body:
		respBody[64] = 0x41 // StructureSize = 65
		respBody[66] = 0x01 // SecurityMode = Signing Enabled
		respBody[68] = 0x11 // Dialect = 0x0311 (SMB 3.1.1)
		respBody[69] = 0x03
		respBody[70] = 0x01 // NegotiateContextCount = 1
		// Capabilities (offset 64+24 = 88)
		respBody[88] = 0x41 // DFS (0x01) | Encryption (0x40)

		// SystemTime (offset 64+40 = 104) -> current FILETIME
		nowFt := uint64((time.Now().UnixNano() / 100) + 116444736000000000)
		binary.LittleEndian.PutUint64(respBody[104:112], nowFt)

		// NegotiateContextOffset (offset 64+64 = 128)
		binary.LittleEndian.PutUint32(respBody[128:132], 136)

		// Context at offset 136 (SMB2_ENCRYPTION_CAPABILITIES = 0x0002)
		ctxOffset := 136
		binary.LittleEndian.PutUint16(respBody[ctxOffset:ctxOffset+2], 0x0002) // Type
		binary.LittleEndian.PutUint16(respBody[ctxOffset+2:ctxOffset+4], 4)     // Length
		binary.LittleEndian.PutUint16(respBody[ctxOffset+8:ctxOffset+10], 1)   // CipherCount
		binary.LittleEndian.PutUint16(respBody[ctxOffset+10:ctxOffset+12], 2)  // AES-128-GCM

		payloadLen := len(respBody)
		tcpHeader := []byte{0x00, byte((payloadLen >> 16) & 0xff), byte((payloadLen >> 8) & 0xff), byte(payloadLen & 0xff)}
		conn.Write(append(tcpHeader, respBody...))
	}()

	smb := NewSMBing(SMBOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := smb.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "SMB 3.1.1")
	assert.Contains(t, res.Diagnostics, "Signing: Enabled")
	assert.Contains(t, res.Diagnostics, "AES-128-GCM")
	assert.Contains(t, res.Diagnostics, "ClockSkew")
}

func TestSSHing_KEXINIT(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Send SSH server banner
		conn.Write([]byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu0.1\r\n"))

		// Read client banner
		buf := make([]byte, 128)
		_, err = conn.Read(buf)
		if err != nil {
			return
		}

		// Build a mock SSH_MSG_KEXINIT packet
		var payload bytes.Buffer
		payload.WriteByte(20)              // msg type = SSH_MSG_KEXINIT
		payload.Write(make([]byte, 16))    // cookie (16 bytes)

		// helper to write SSH name-list
		writeNameList := func(list string) {
			binary.Write(&payload, binary.BigEndian, uint32(len(list)))
			payload.WriteString(list)
		}

		writeNameList("curve25519-sha256,ecdh-sha2-nistp256")     // kex
		writeNameList("ssh-ed25519,rsa-sha2-512,rsa-sha2-256")    // host keys
		writeNameList("chacha20-poly1305@openssh.com,aes256-gcm") // enc c2s
		writeNameList("chacha20-poly1305@openssh.com,aes256-gcm") // enc s2c
		writeNameList("umac-128-etm@openssh.com,hmac-sha2-512")   // mac c2s
		writeNameList("umac-128-etm@openssh.com,hmac-sha2-512")   // mac s2c
		writeNameList("none,zlib@openssh.com")                    // comp c2s
		writeNameList("none,zlib@openssh.com")                    // comp s2c
		writeNameList("")                                         // lang c2s
		writeNameList("")                                         // lang s2c
		payload.WriteByte(0)                                      // first_kex_packet_follows = false
		binary.Write(&payload, binary.BigEndian, uint32(0))       // reserved

		paddingLen := byte(8 - ((payload.Len() + 5) % 8))
		if paddingLen < 4 {
			paddingLen += 8
		}
		packetLen := uint32(payload.Len() + 1 + int(paddingLen))

		var packet bytes.Buffer
		binary.Write(&packet, binary.BigEndian, packetLen)
		packet.WriteByte(paddingLen)
		packet.Write(payload.Bytes())
		packet.Write(make([]byte, paddingLen))

		conn.Write(packet.Bytes())
	}()

	sshing := NewSSHing(SSHOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := sshing.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "OpenSSH_9.6p1")
	assert.Contains(t, res.Diagnostics, "curve25519-sha256")
	assert.Contains(t, res.Diagnostics, "ssh-ed25519")
	assert.Contains(t, res.Diagnostics, "chacha20-poly1305@openssh.com")
}

func TestRsyncing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Send Rsync daemon greeting
		conn.Write([]byte("@RSYNCD: 31.0 digest=md4,md5,sha1,sha256,sha512\n"))

		reader := bufio.NewReader(conn)
		_, _ = reader.ReadString('\n') // read client greeting

		// Read #list command and reply with module list
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(line) == "#list" {
			conn.Write([]byte("backup\tServer backup repository\nftp\tPublic FTP mirror\n@RSYNCD: EXIT\n"))
		}
	}()

	rsync := NewRsyncing(RsyncOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := rsync.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "RSYNCD 31.0")
	assert.Contains(t, res.Diagnostics, "sha256")
	assert.Contains(t, res.Diagnostics, "backup")
	assert.Contains(t, res.Diagnostics, "ftp")
}

func TestFTPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Send 220 banner
		conn.Write([]byte("220-Welcome to Pure-FTPd\r\n220 Ready.\r\n"))

		reader := bufio.NewReader(conn)
		for {
			cmd, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			cmdTrim := strings.TrimSpace(cmd)
			if cmdTrim == "FEAT" {
				conn.Write([]byte("211-Extensions supported:\r\n AUTH TLS\r\n UTF8\r\n SIZE\r\n MDTM\r\n211 End.\r\n"))
			} else if cmdTrim == "QUIT" {
				conn.Write([]byte("221 Goodbye.\r\n"))
				break
			}
		}
	}()

	ftp := NewFTPing(FTPOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := ftp.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "Ready")
	assert.Contains(t, res.Diagnostics, "AUTH TLS")
	assert.Contains(t, res.Diagnostics, "UTF8")
	assert.Contains(t, res.Diagnostics, "SIZE")
}

func TestO365ing_MockServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("request-id", "req-12345")
		w.Header().Set("x-ms-request-id", "ms-req-67890")
		w.Header().Set("X-FEServer", "FE-SERVER-01")
		w.Header().Set("X-CalculatedBETarget", "BE-SERVER-02")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	parts := strings.Split(strings.TrimPrefix(ts.URL, "https://"), ":")
	portNum, _ := strconv.Atoi(parts[1])

	o := NewO365ing(O365Options{
		Hostname:   parts[0],
		IP:         netip.MustParseAddr(parts[0]),
		Port:       uint16(portNum),
		SkipVerify: true,
		Timeout:    2 * time.Second,
	})

	res := o.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusOK, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "200 OK")
	assert.Contains(t, res.Diagnostics, "FE: FE-SERVER-01")
}

func TestStorageing_MockS3BlobGCS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-amz-request-id", "amz-req-111")
		w.Header().Set("x-amz-id-2", "amz-host-222")
		w.Header().Set("x-ms-request-id", "ms-req-333")
		w.Header().Set("x-guploader-uploadid", "gcs-upload-444")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	parts := strings.Split(strings.TrimPrefix(ts.URL, "https://"), ":")
	portNum, _ := strconv.Atoi(parts[1])

	for _, typ := range []StorageType{StorageS3, StorageAzureBlob, StorageGCS} {
		st := NewStorageing(StorageOptions{
			Hostname:   parts[0],
			IP:         netip.MustParseAddr(parts[0]),
			Port:       uint16(portNum),
			Type:       typ,
			SkipVerify: true,
			Timeout:    2 * time.Second,
		})

		res := st.Ping(context.Background())
		assert.NoError(t, res.Err)
		assert.Equal(t, http.StatusOK, res.HTTPStatus)
		assert.Contains(t, res.Diagnostics, "HTTP 200")
		assert.Contains(t, res.Diagnostics, "RequestID: amz-req-111")
	}
}

func TestQueueing_MockRabbitMQ(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		protoHeader := make([]byte, 8)
		_, _ = conn.Read(protoHeader)

		// AMQP Connection.Start frame (Type: 1, Channel: 0, Payload: Class 10, Method 10)
		frame := []byte{
			0x01,       // Frame type METHOD
			0x00, 0x00, // Channel 0
			0x00, 0x00, 0x00, 0x20, // Length 32
			0x00, 0x0a, // Class 10 (Connection)
			0x00, 0x0a, // Method 10 (Start)
			0x00, 0x09, // Version Major 0, Minor 9
			// Properties field table
			0x00, 0x00, 0x00, 0x10,
			'v', 'e', 'r', 's', 'i', 'o', 'n', 'S', 0x00, 0x00, 0x00, 0x05, '3', '.', '1', '2',
			0xce, // Frame end
		}
		conn.Write(frame)
	}()

	q := NewQueueing(QueueOptions{
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(p),
		Protocol: QueueRabbitMQ,
		Timeout:  2 * time.Second,
	})

	res := q.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "AMQP 0-9-1")
}

func TestQueueing_MockKafka(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reqHeader := make([]byte, 19)
		_, _ = conn.Read(reqHeader)

		// Kafka ApiVersions response (4-byte length, 4-byte correlation ID 1, 2-byte error code 0, 4-byte api keys count 5)
		resp := make([]byte, 14)
		binary.BigEndian.PutUint32(resp[0:4], 10)  // length after size
		binary.BigEndian.PutUint32(resp[4:8], 1)   // correlation ID
		binary.BigEndian.PutUint16(resp[8:10], 0)  // error code 0
		binary.BigEndian.PutUint32(resp[10:14], 5) // 5 API keys
		_, _ = conn.Write(resp)
		time.Sleep(50 * time.Millisecond)
	}()

	k := NewQueueing(QueueOptions{
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(p),
		Protocol: QueueKafka,
		Timeout:  2 * time.Second,
	})

	res := k.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "Kafka: ApiVersions")
}

func TestSSHing_MockServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		conn.Write([]byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"))
	}()

	ssh := NewSSHing(SSHOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := ssh.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "OpenSSH_9.6p1")
}

func TestSMBing_MockServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 256)
		_, _ = conn.Read(buf)

		// SMB2 Negotiate Response header (\xFE SMB)
		resp := make([]byte, 68)
		resp[0] = 0x00
		resp[1] = 0x00
		resp[2] = 0x00
		resp[3] = 0x40 // NetBIOS length 64
		copy(resp[4:8], []byte{0xfe, 'S', 'M', 'B'}) // SMB2 magic
		binary.LittleEndian.PutUint16(resp[8:10], 64) // StructureSize 64
		binary.LittleEndian.PutUint16(resp[70-4:72-4], 0x0311) // Dialect 3.1.1
		conn.Write(resp)
	}()

	smb := NewSMBing(SMBOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := smb.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "SMB")
}

func TestICMPing_Localhost(t *testing.T) {
	icmp := NewICMPing(ICMPOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Timeout: time.Second,
	})

	// On non-privileged Windows/Linux, may require root/admin or fallback
	_ = icmp.Ping(context.Background())
}

func TestTLSing_MockTLSServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	parts := strings.Split(strings.TrimPrefix(ts.URL, "https://"), ":")
	portNum, _ := strconv.Atoi(parts[1])

	tlsProber := NewTLSing(TLSOptions{
		Hostname:   parts[0],
		IP:         netip.MustParseAddr(parts[0]),
		Port:       uint16(portNum),
		SkipVerify: true,
		Timeout:    2 * time.Second,
	})

	res := tlsProber.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "TLS")
}

func TestMemcacheding_MockServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		line, _ := reader.ReadString('\n')
		if strings.HasPrefix(line, "version") {
			conn.Write([]byte("VERSION 1.6.22\r\n"))
		}
	}()

	mc := NewMemcacheding(MemcachedOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := mc.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "1.6.22")
}

type dummyPrinter struct{}

func (d *dummyPrinter) PrintProbeSuccess(s *stats.Statistics) {}
func (d *dummyPrinter) PrintProbeFailure(s *stats.Statistics) {}
func (d *dummyPrinter) PrintTotalDownTime(s *stats.Statistics) {}
func (d *dummyPrinter) PrintRetryingToResolve(hostname string) {}
func (d *dummyPrinter) PrintError(format string, args ...any)  {}

func TestProber_RetryExecution(t *testing.T) {
	ln, port := startTCPTestServer(t)
	defer ln.Close()

	st := stats.NewStatistics(stats.Options{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     port,
	})

	pinger := NewTcping(TCPOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    port,
		Timeout: 2 * time.Second,
	})

	prober := NewProber(pinger, &dummyPrinter{}, st, Options{
		Timeout:               2 * time.Second,
		IntervalBetweenProbes: 5 * time.Millisecond,
		ProbesBeforeQuit:      1,
		Retries:               2,
		InitialRetryBackoff:   5 * time.Millisecond,
		MaxRetryBackoff:       20 * time.Millisecond,
		RetryJitter:           true,
	})

	finalStats, err := prober.Probe(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, finalStats)
	assert.Equal(t, 1, st.Successful)
}

func TestDBing_MockMySQL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// MySQL HandshakeV10 packet: 3 bytes length, 1 byte sequence (0), protocol 10, version "8.0.36\x00"
		versionStr := "8.0.36-MySQL"
		payload := []byte{0x0a} // protocol 10
		payload = append(payload, []byte(versionStr)...)
		payload = append(payload, 0x00) // null terminator
		payload = append(payload, 0x01, 0x00, 0x00, 0x00) // connection ID
		payload = append(payload, make([]byte, 8)...)      // auth plugin data part 1
		payload = append(payload, 0x00)                    // filter
		payload = append(payload, 0xff, 0xf7)              // capability flags
		payload = append(payload, 0x21)                    // character set utf8mb4
		payload = append(payload, 0x02, 0x00)              // status flags

		pkt := make([]byte, 4+len(payload))
		pkt[0] = byte(len(payload) & 0xff)
		pkt[1] = byte((len(payload) >> 8) & 0xff)
		pkt[2] = byte((len(payload) >> 16) & 0xff)
		pkt[3] = 0x00 // seq 0
		copy(pkt[4:], payload)

		conn.Write(pkt)
	}()

	db := NewDBing(DBOptions{
		Type:    MySQL,
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "8.0.36")
}

func TestDBing_MockPostgreSQL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		sslReq := make([]byte, 8)
		_, _ = conn.Read(sslReq)
		conn.Write([]byte{'N'}) // No SSL

		startupBuf := make([]byte, 256)
		_, _ = conn.Read(startupBuf)

		// Send ErrorResponse packet: 'E', 4-byte length, severity 'S' "FATAL", 'M' "database netping does not exist", '\0'
		errPkt := []byte{'E', 0x00, 0x00, 0x00, 0x20, 'S', 'F', 'A', 'T', 'A', 'L', 0x00, 'M', 'P', 'o', 's', 't', 'g', 'r', 'e', 'S', 'Q', 'L', ' ', 'O', 'K', 0x00, 0x00}
		conn.Write(errPkt)
	}()

	db := NewDBing(DBOptions{
		Type:    PostgreSQL,
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "PostgreSQL")
}

func TestMailing_MockSMTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		conn.Write([]byte("220 mail.example.com ESMTP Postfix\r\n"))

		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			lineTrim := strings.TrimSpace(line)
			if strings.HasPrefix(lineTrim, "EHLO") {
				conn.Write([]byte("250-mail.example.com\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 HELP\r\n"))
			} else if lineTrim == "QUIT" {
				conn.Write([]byte("221 2.0.0 Bye\r\n"))
				break
			}
		}
	}()

	m := NewMailing(MailOptions{
		Protocol: MailSMTP,
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(p),
		Timeout:  2 * time.Second,
	})

	res := m.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "ESMTP Postfix")
	assert.Contains(t, res.Diagnostics, "STARTTLS")
}

func TestMailing_MockIMAP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		conn.Write([]byte("* OK [CAPABILITY IMAP4rev1 SASL-IR STARTTLS AUTH=PLAIN] Dovecot ready.\r\n"))

		reader := bufio.NewReader(conn)
		line, _ := reader.ReadString('\n')
		if strings.Contains(line, "CAPABILITY") {
			conn.Write([]byte("* CAPABILITY IMAP4rev1 SASL-IR STARTTLS AUTH=PLAIN\r\nA001 OK Capability completed.\r\n"))
		}
	}()

	m := NewMailing(MailOptions{
		Protocol: MailIMAP,
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(p),
		Timeout:  2 * time.Second,
	})

	res := m.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "Dovecot ready")
	assert.Contains(t, res.Diagnostics, "IMAP4rev1")
}

func TestMailing_MockPOP3(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		conn.Write([]byte("+OK Dovecot ready.\r\n"))

		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			lineTrim := strings.TrimSpace(line)
			if lineTrim == "CAPA" {
				conn.Write([]byte("+OK\r\nSTLS\r\nTOP\r\nUSER\r\nSASL PLAIN\r\n.\r\n"))
			} else if lineTrim == "QUIT" {
				conn.Write([]byte("+OK Logging out\r\n"))
				break
			}
		}
	}()

	m := NewMailing(MailOptions{
		Protocol: MailPOP3,
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(p),
		Timeout:  2 * time.Second,
	})

	res := m.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "Dovecot ready")
	assert.Contains(t, res.Diagnostics, "STLS")
}

func TestDBing_MockMSSQL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		prelogin := make([]byte, 32)
		_, _ = conn.Read(prelogin)

		// Send TDS PRELOGIN response (Header: Type 0x04, Status 0x01, Length 29)
		// Body: Token 0 (VERSION offset 11, len 6), Token 1 (ENCRYPTION offset 17, len 1), Term 0xFF
		body := []byte{
			0x00, 0x00, 0x0b, 0x00, 0x06, // Option 0: VERSION offset 11, len 6
			0x01, 0x00, 0x11, 0x00, 0x01, // Option 1: ENCRYPTION offset 17, len 1
			0xff,                         // Terminator
			0x10, 0x00, 0x03, 0xe8, 0x00, 0x00, // Version: 16.0.1000 (SQL Server 2022)
			0x00,                         // ENCRYPT_OFF
		}
		header := []byte{0x04, 0x01, 0x00, byte(8 + len(body)), 0x00, 0x00, 0x00, 0x00}
		conn.Write(append(header, body...))
	}()

	db := NewDBing(DBOptions{
		Type:    MSSQL,
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "SQL Server 2022")
	assert.Contains(t, res.Diagnostics, "Encryption: Off")
}

func TestDBing_MockOracle(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		tnsReq := make([]byte, 256)
		_, _ = conn.Read(tnsReq)

		// Send TNS ACCEPT packet: Length 32 (0x00 0x20), Packet Checksum 0, Type 2 (ACCEPT), Flags 0, Checksum 0
		// Payload: TNS Version 316 (0x01 0x3c), Options 0, SDU 8192 (0x20 0x00)
		tnsAccept := []byte{
			0x00, 0x20, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x01, 0x3c, 0x00, 0x00, 0x20, 0x00, 0x7f, 0xff,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
		conn.Write(tnsAccept)
	}()

	db := NewDBing(DBOptions{
		Type:        Oracle,
		IP:          netip.MustParseAddr("127.0.0.1"),
		Port:        uint16(p),
		ServiceName: "FREE",
		Timeout:     2 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "TNS: ACCEPT")
	assert.Contains(t, res.Diagnostics, "TNS v316")
}

func TestDBing_MockMongoDB(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		helloBuf := make([]byte, 128)
		_, _ = conn.Read(helloBuf)

		// Build BSON body with "version": "7.0.5", "ok": 1.0
		var bsonDoc bytes.Buffer
		bsonDoc.WriteByte(0x02) // string
		bsonDoc.WriteString("version\x00\x06\x00\x00\x007.0.5\x00")
		bsonDoc.WriteByte(0x10) // int32
		bsonDoc.WriteString("maxWireVersion\x00\x15\x00\x00\x00") // 21
		bsonDoc.WriteByte(0x00) // end doc

		docBytes := bsonDoc.Bytes()
		totalDocLen := uint32(len(docBytes) + 4)
		var fullDoc []byte
		fullDoc = append(fullDoc, byte(totalDocLen), byte(totalDocLen>>8), byte(totalDocLen>>16), byte(totalDocLen>>24))
		fullDoc = append(fullDoc, docBytes...)

		// OP_MSG Section 0
		var section0 []byte
		section0 = append(section0, 0x00) // Kind 0
		section0 = append(section0, fullDoc...)

		// OP_MSG MsgHeader (16 bytes) + FlagBits (4 bytes) + Section0
		totalMsgLen := uint32(16 + 4 + len(section0))
		msgHeader := make([]byte, 20)
		binary.LittleEndian.PutUint32(msgHeader[0:4], totalMsgLen)
		binary.LittleEndian.PutUint32(msgHeader[4:8], 2) // Response ID 2
		binary.LittleEndian.PutUint32(msgHeader[8:12], 1) // ResponseTo 1
		binary.LittleEndian.PutUint32(msgHeader[12:16], 2013) // OP_MSG (2013)
		binary.LittleEndian.PutUint32(msgHeader[16:20], 0) // FlagBits 0

		conn.Write(append(msgHeader, section0...))
	}()

	db := NewDBing(DBOptions{
		Type:    MongoDB,
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "7.0.5")
	assert.Contains(t, res.Diagnostics, "OP_MSG")
}

func TestDBing_MockCassandra(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		startup := make([]byte, 64)
		_, _ = conn.Read(startup)

		// CQL v4 READY frame: 0x84 (v4 response), 0x00 (flags), 0x00 0x01 (stream 1), 0x02 (READY), 0x00 0x00 0x00 0x00 (len 0)
		readyFrame := []byte{0x84, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00}
		conn.Write(readyFrame)
	}()

	db := NewDBing(DBOptions{
		Type:    Cassandra,
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "CQL: v4/v5 (READY)")
}

func TestDBing_MockSAPHANA(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		initBuf := make([]byte, 32)
		_, _ = conn.Read(initBuf)

		// SAP HANA Init reply: Major 4, Minor 20 (Proto 4.20)
		reply := []byte{0x04, 0x14, 0x00, 0x04, 0x01, 0x00, 0x00, 0x01}
		conn.Write(reply)
	}()

	db := NewDBing(DBOptions{
		Type:    SAPHANA,
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "SAP HANA 2.0")
}

func TestDNSQueryProber_UDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer pc.Close()

	portNum := uint16(pc.LocalAddr().(*net.UDPAddr).Port)

	go func() {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n < 12 {
			return
		}
		// Echo back valid DNS response: ID (bytes 0-1), Flags (0x8180 Standard response, NoError), QDCOUNT 1, ANCOUNT 1
		resp := make([]byte, n+16)
		copy(resp[:n], buf[:n])
		resp[2] = 0x81 // QR=1, Opcode=0, AA=0, TC=0, RD=1
		resp[3] = 0x80 // RA=1, Z=0, RCODE=0 (NOERROR)
		resp[6] = 0x00
		resp[7] = 0x01 // ANCOUNT 1

		// Append Answer: Pointer to name (0xc0 0x0c), Type A (0x00 0x01), Class IN (0x00 0x01), TTL 300 (0x00 0x00 0x01 0x2c), DataLen 4 (0x00 0x04), IP 192.0.2.1
		ans := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 192, 0, 2, 1}
		copy(resp[n:], ans)

		pc.WriteTo(resp, addr)
	}()

	dq := NewDNSQueryProber(DNSQueryOptions{
		Nameserver: "127.0.0.1",
		IP:         netip.MustParseAddr("127.0.0.1"),
		Port:       portNum,
		Domains:    []string{"test.example.com"},
		Timeout:    2 * time.Second,
	})

	res := dq.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "NOERROR")
	assert.Contains(t, res.Diagnostics, "192.0.2.1")
}

func TestDNSQueryProber_DoH(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) < 12 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Build DNS answer
		resp := make([]byte, len(body)+16)
		copy(resp[:len(body)], body)
		resp[2] = 0x81
		resp[3] = 0x80
		resp[6] = 0x00
		resp[7] = 0x01
		ans := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 10, 0, 0, 1}
		copy(resp[len(body):], ans)

		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	}))
	defer ts.Close()

	parts := strings.Split(strings.TrimPrefix(ts.URL, "https://"), ":")
	portNum, _ := strconv.Atoi(parts[1])

	dq := NewDNSQueryProber(DNSQueryOptions{
		Nameserver: parts[0],
		IP:         netip.MustParseAddr(parts[0]),
		Port:       uint16(portNum),
		Domains:    []string{"doh.example.com"},
		IsDoH:      true,
		Timeout:    2 * time.Second,
	})
	dq.httpClient = ts.Client()

	res := dq.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "NOERROR")
	assert.Contains(t, res.Diagnostics, "10.0.0.1")
}

func TestGRPCing_MockServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("grpc-status", "0")
		w.Header().Set("grpc-message", "OK")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	parts := strings.Split(strings.TrimPrefix(ts.URL, "http://"), ":")
	portNum, _ := strconv.Atoi(parts[1])

	grpcProber := NewGRPCing(GRPCOptions{
		Hostname: parts[0],
		IP:       netip.MustParseAddr(parts[0]),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := grpcProber.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "gRPC: 0 (OK)")
}

func TestLDAPing_MockServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		bindReq := make([]byte, 64)
		_, _ = conn.Read(bindReq)

		// RFC 4511 BindResponse (Success 0):
		// Sequence (14 bytes):
		//   MessageID: 1 (INTEGER 1) (0x02 0x01 0x01)
		//   BindResponse (Tag 0x61, 7 bytes):
		//     ResultCode: 0 (ENUMERATED 0) (0x0a 0x01 0x00)
		//     MatchedDN: "" (OCTET STRING 0) (0x04 0x00)
		//     DiagnosticMessage: "" (OCTET STRING 0) (0x04 0x00)
		bindResp := []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
		conn.Write(bindResp)
	}()

	ldapProber := NewLDAPing(LDAPOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := ldapProber.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "SUCCESS")
}

func TestWSing_MockServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Sec-WebSocket-Key")
		h := sha1.New()
		h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", acceptKey)
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer ts.Close()

	parts := strings.Split(strings.TrimPrefix(ts.URL, "http://"), ":")
	portNum, _ := strconv.Atoi(parts[1])

	ws := NewWSing(WSOptions{
		Hostname: parts[0],
		IP:       netip.MustParseAddr(parts[0]),
		Port:     uint16(portNum),
		Timeout:  2 * time.Second,
	})

	res := ws.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, 101, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "101 Switching Protocols")
}

func TestFTPing_MockServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		conn.Write([]byte("220 ProFTPD Server ready.\r\n"))

		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			lineTrim := strings.TrimSpace(line)
			if strings.HasPrefix(lineTrim, "FEAT") {
				conn.Write([]byte("211-Features:\r\n AUTH TLS\r\n UTF8\r\n211 End\r\n"))
			} else if strings.HasPrefix(lineTrim, "QUIT") {
				conn.Write([]byte("221 Goodbye.\r\n"))
				break
			}
		}
	}()

	ftp := NewFTPing(FTPOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := ftp.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "ProFTPD")
}

func TestRsyncing_MockServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		conn.Write([]byte("@RSYNCD: 31.0\n"))

		reader := bufio.NewReader(conn)
		line, _ := reader.ReadString('\n')
		if strings.HasPrefix(line, "@RSYNCD:") {
			conn.Write([]byte("@RSYNCD: OK\n"))
		}
	}()

	rsync := NewRsyncing(RsyncOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := rsync.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "RSYNCD")
}

func TestRedising_MockServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	parts := strings.Split(ln.Addr().String(), ":")
	p, err := strconv.Atoi(parts[len(parts)-1])
	assert.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			if strings.Contains(line, "PING") {
				conn.Write([]byte("+PONG\r\n"))
			} else if strings.Contains(line, "INFO") {
				info := "# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\nos:Linux\r\n"
				conn.Write([]byte(fmt.Sprintf("$%d\r\n%s\r\n", len(info), info)))
			}
		}
	}()

	redis := NewRedising(RedisOptions{
		IP:      netip.MustParseAddr("127.0.0.1"),
		Port:    uint16(p),
		Timeout: 2 * time.Second,
	})

	res := redis.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "7.2.4")
}

func TestHTTPing_MockHTTPServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, World!"))
	}))
	defer ts.Close()

	parts := strings.Split(strings.TrimPrefix(ts.URL, "http://"), ":")
	portNum, _ := strconv.Atoi(parts[1])

	httpProber := NewHTTPing(HTTPOptions{
		Hostname: parts[0],
		IP:       netip.MustParseAddr(parts[0]),
		Port:     uint16(portNum),
		Protocol: consts.HTTP,
		Timeout:  2 * time.Second,
	})

	res := httpProber.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, 200, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "nginx/1.24.0")
}

func TestHTTPing_MockHTTPSServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Caddy")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	parts := strings.Split(strings.TrimPrefix(ts.URL, "https://"), ":")
	portNum, _ := strconv.Atoi(parts[1])

	httpsProber := NewHTTPing(HTTPOptions{
		Hostname: parts[0],
		IP:       netip.MustParseAddr(parts[0]),
		Port:     uint16(portNum),
		Protocol: consts.HTTPS,
		Timeout:  2 * time.Second,
	})
	httpsProber.client = ts.Client()

	res := httpsProber.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, 200, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "Caddy")
}

func TestFormatBytesSize(t *testing.T) {
	assert.Equal(t, "1.5GB", formatBytesSize("1610612736"))
	assert.Equal(t, "50MB", formatBytesSize("52428800"))
	assert.Equal(t, "500KB", formatBytesSize("512000"))
	assert.Equal(t, "500B", formatBytesSize("500"))
	assert.Equal(t, "invalid", formatBytesSize("invalid"))
	assert.Equal(t, "-10", formatBytesSize("-10"))
}








