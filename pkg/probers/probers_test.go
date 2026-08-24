// Test Strategy (pkg/probers - Protocol Diagnostics):
//  1. Protocol Handshake Simulation: Spin up mock TCP, TLS, HTTP, DNS, DB, Mail, Queue, and Storage servers.
//  2. Wire-Level Frame Inspection: Validate binary framing, BER/ASN.1 structures, BSON serialization, and TNS negotiation.
//  3. Timing & TTFB Metrics: Verify RTT, DNS time, TCP connect time, TLS handshake time, and TTFB calculations.
//  4. Diagnostic Header Parsing: Validate TLS ciphers, certificate expiration, HTTP headers, and DB banner extraction.
//  5. Error Taxonomy & Resilience: Test connection timeouts, malformed server responses, and fast connection resets.
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
					0xff,                               // Terminator
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
		binary.LittleEndian.PutUint16(respBody[ctxOffset+2:ctxOffset+4], 4)    // Length
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
		payload.WriteByte(20)           // msg type = SSH_MSG_KEXINIT
		payload.Write(make([]byte, 16)) // cookie (16 bytes)

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
		resp[3] = 0x40                                         // NetBIOS length 64
		copy(resp[4:8], []byte{0xfe, 'S', 'M', 'B'})           // SMB2 magic
		binary.LittleEndian.PutUint16(resp[8:10], 64)          // StructureSize 64
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

func (d *dummyPrinter) PrintProbeSuccess(s *stats.Statistics)  {}
func (d *dummyPrinter) PrintProbeFailure(s *stats.Statistics)  {}
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
		payload = append(payload, 0x00)                   // null terminator
		payload = append(payload, 0x01, 0x00, 0x00, 0x00) // connection ID
		payload = append(payload, make([]byte, 8)...)     // auth plugin data part 1
		payload = append(payload, 0x00)                   // filter
		payload = append(payload, 0xff, 0xf7)             // capability flags
		payload = append(payload, 0x21)                   // character set utf8mb4
		payload = append(payload, 0x02, 0x00)             // status flags

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
			0xff,                               // Terminator
			0x10, 0x00, 0x03, 0xe8, 0x00, 0x00, // Version: 16.0.1000 (SQL Server 2022)
			0x00, // ENCRYPT_OFF
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
		bsonDoc.WriteByte(0x10)                                   // int32
		bsonDoc.WriteString("maxWireVersion\x00\x15\x00\x00\x00") // 21
		bsonDoc.WriteByte(0x00)                                   // end doc

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
		binary.LittleEndian.PutUint32(msgHeader[4:8], 2)      // Response ID 2
		binary.LittleEndian.PutUint32(msgHeader[8:12], 1)     // ResponseTo 1
		binary.LittleEndian.PutUint32(msgHeader[12:16], 2013) // OP_MSG (2013)
		binary.LittleEndian.PutUint32(msgHeader[16:20], 0)    // FlagBits 0

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

func TestHTTPing_SendDataAndExpectData(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if string(body) == `{"health":"ping"}` {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"healthy","uptime":3600}`))
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("bad payload"))
			return
		}
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("pong-response-body-ready"))
			return
		}
		// Default HEAD
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	parts := strings.Split(strings.TrimPrefix(ts.URL, "http://"), ":")
	portNum, _ := strconv.Atoi(parts[1])

	// 1. Test POST with SendData and ExpectData matching
	postProber := NewHTTPing(HTTPOptions{
		Hostname:   parts[0],
		IP:         netip.MustParseAddr(parts[0]),
		Port:       uint16(portNum),
		Protocol:   consts.HTTP,
		Timeout:    2 * time.Second,
		SendData:   `{"health":"ping"}`,
		ExpectData: `"status":"healthy"`,
	})
	postRes := postProber.Ping(context.Background())
	assert.NoError(t, postRes.Err)
	assert.Equal(t, 200, postRes.HTTPStatus)
	assert.Contains(t, postRes.Diagnostics, `Sent: 17B`)
	assert.Contains(t, postRes.Diagnostics, `Matched: "\"status\":\"healthy\""`)

	// 2. Test GET with ExpectData success
	getProber := NewHTTPing(HTTPOptions{
		Hostname:   parts[0],
		IP:         netip.MustParseAddr(parts[0]),
		Port:       uint16(portNum),
		Protocol:   consts.HTTP,
		Timeout:    2 * time.Second,
		ExpectData: "pong-response",
	})
	getRes := getProber.Ping(context.Background())
	assert.NoError(t, getRes.Err)
	assert.Equal(t, 200, getRes.HTTPStatus)
	assert.Contains(t, getRes.Diagnostics, `Matched: "pong-response"`)

	// 3. Test GET with ExpectData mismatch
	mismatchProber := NewHTTPing(HTTPOptions{
		Hostname:   parts[0],
		IP:         netip.MustParseAddr(parts[0]),
		Port:       uint16(portNum),
		Protocol:   consts.HTTP,
		Timeout:    2 * time.Second,
		ExpectData: "missing-token",
	})
	mismatchRes := mismatchProber.Ping(context.Background())
	assert.Error(t, mismatchRes.Err)
	assert.Contains(t, mismatchRes.Err.Error(), `expected "missing-token" in response`)
}

func TestFormatBytesSize(t *testing.T) {
	assert.Equal(t, "1.5GB", formatBytesSize("1610612736"))
	assert.Equal(t, "50MB", formatBytesSize("52428800"))
	assert.Equal(t, "500KB", formatBytesSize("512000"))
	assert.Equal(t, "500B", formatBytesSize("500"))
	assert.Equal(t, "invalid", formatBytesSize("invalid"))
	assert.Equal(t, "-10", formatBytesSize("-10"))
}

func TestDatabase_Helpers(t *testing.T) {
	assert.Equal(t, uint16(3306), defaultDBPort(MySQL, false))
	assert.Equal(t, uint16(1433), defaultDBPort(MSSQL, false))
	assert.Equal(t, uint16(1521), defaultDBPort(Oracle, false))
	assert.Equal(t, uint16(2484), defaultDBPort(Oracle, true))
	assert.Equal(t, uint16(27017), defaultDBPort(MongoDB, false))
	assert.Equal(t, uint16(9042), defaultDBPort(Cassandra, false))
	assert.Equal(t, uint16(30015), defaultDBPort(SAPHANA, false))
	assert.Equal(t, uint16(5432), defaultDBPort(PostgreSQL, false))

	assert.Equal(t, "SQL Server 2022", mssqlReleaseName(16))
	assert.Equal(t, "SQL Server 2019", mssqlReleaseName(15))
	assert.Equal(t, "SQL Server 2017", mssqlReleaseName(14))
	assert.Equal(t, "SQL Server 2016", mssqlReleaseName(13))
	assert.Equal(t, "SQL Server 2014", mssqlReleaseName(12))
	assert.Equal(t, "SQL Server 2012", mssqlReleaseName(11))
	assert.Equal(t, "SQL Server 2008", mssqlReleaseName(10))
	assert.Equal(t, "SQL Server v9", mssqlReleaseName(9))

	assert.Equal(t, "Oracle 19c/21c/23c", tnsProtocolRelease(316))
	assert.Equal(t, "Oracle 18c", tnsProtocolRelease(315))
	assert.Equal(t, "Oracle 12c R2", tnsProtocolRelease(314))
	assert.Equal(t, "Oracle 12c R1", tnsProtocolRelease(313))
	assert.Equal(t, "Oracle 11g R2", tnsProtocolRelease(312))
	assert.Equal(t, "Oracle 11g R1", tnsProtocolRelease(311))
	assert.Equal(t, "Oracle 10g", tnsProtocolRelease(310))
	assert.Equal(t, "Oracle TNS v300", tnsProtocolRelease(300))
}

func TestGRPC_StatusNames(t *testing.T) {
	assert.Equal(t, "OK", grpcStatusName("0"))
	assert.Equal(t, "CANCELLED", grpcStatusName("1"))
	assert.Equal(t, "UNKNOWN", grpcStatusName("2"))
	assert.Equal(t, "INVALID_ARGUMENT", grpcStatusName("3"))
	assert.Equal(t, "DEADLINE_EXCEEDED", grpcStatusName("4"))
	assert.Equal(t, "NOT_FOUND", grpcStatusName("5"))
	assert.Equal(t, "ALREADY_EXISTS", grpcStatusName("6"))
	assert.Equal(t, "PERMISSION_DENIED", grpcStatusName("7"))
	assert.Equal(t, "RESOURCE_EXHAUSTED", grpcStatusName("8"))
	assert.Equal(t, "FAILED_PRECONDITION", grpcStatusName("9"))
	assert.Equal(t, "ABORTED", grpcStatusName("10"))
	assert.Equal(t, "OUT_OF_RANGE", grpcStatusName("11"))
	assert.Equal(t, "UNIMPLEMENTED", grpcStatusName("12"))
	assert.Equal(t, "INTERNAL", grpcStatusName("13"))
	assert.Equal(t, "UNAVAILABLE", grpcStatusName("14"))
	assert.Equal(t, "DATA_LOSS", grpcStatusName("15"))
	assert.Equal(t, "UNAUTHENTICATED", grpcStatusName("16"))
	assert.Equal(t, "CODE_99", grpcStatusName("99"))
}

func TestLDAP_ResultCodeNames(t *testing.T) {
	assert.Equal(t, "SUCCESS", ldapResultCodeName(0))
	assert.Equal(t, "OPERATIONS_ERROR", ldapResultCodeName(1))
	assert.Equal(t, "PROTOCOL_ERROR", ldapResultCodeName(2))
	assert.Equal(t, "AUTH_METHOD_NOT_SUPPORTED", ldapResultCodeName(7))
	assert.Equal(t, "STRONGER_AUTH_REQUIRED", ldapResultCodeName(8))
	assert.Equal(t, "SASL_BIND_IN_PROGRESS", ldapResultCodeName(14))
	assert.Equal(t, "NO_SUCH_OBJECT", ldapResultCodeName(32))
	assert.Equal(t, "INVALID_DN_SYNTAX", ldapResultCodeName(34))
	assert.Equal(t, "INAPPROPRIATE_AUTH", ldapResultCodeName(48))
	assert.Equal(t, "INVALID_CREDENTIALS", ldapResultCodeName(49))
	assert.Equal(t, "INSUFFICIENT_ACCESS_RIGHTS", ldapResultCodeName(50))
	assert.Equal(t, "BUSY", ldapResultCodeName(51))
	assert.Equal(t, "UNAVAILABLE", ldapResultCodeName(52))
	assert.Equal(t, "UNWILLING_TO_PERFORM", ldapResultCodeName(53))
	assert.Equal(t, "RESULT", ldapResultCodeName(99))
}

func TestMemcached_FormatBytes(t *testing.T) {
	assert.Equal(t, "500B", formatBytes(500))
	assert.Equal(t, "50K", formatBytes(51200))
	assert.Equal(t, "50.0M", formatBytes(52428800))
	assert.Equal(t, "1.5G", formatBytes(1610612736))
}

func TestSMB_BuildMultiProtocolNegotiatePacket(t *testing.T) {
	pkt := BuildMultiProtocolNegotiatePacket()
	assert.NotEmpty(t, pkt)
	assert.True(t, len(pkt) > 30)
}

func TestMultiProber_Workers_And_Badge(t *testing.T) {
	w1 := TargetWorker{
		Target:   "1.1.1.1:443",
		Host:     "1.1.1.1",
		IP:       netip.MustParseAddr("1.1.1.1"),
		Port:     443,
		Protocol: "HTTPS",
		Stats:    &stats.Statistics{Hostname: "1.1.1.1", Port: 443},
	}
	mp := NewMultiProber([]TargetWorker{w1}, MultiProberOptions{})
	workers := mp.Workers()
	assert.Equal(t, 1, len(workers))
	assert.Equal(t, "1.1.1.1:443", workers[0].Target)

	// Test badge formatting branches
	w2 := TargetWorker{Host: "example.com", IP: netip.MustParseAddr("1.1.1.1"), Port: 443, Protocol: "HTTPS"}
	w3 := TargetWorker{Host: "example.com", Port: 80, Protocol: "HTTP"}
	w4 := TargetWorker{Host: "1.1.1.1", IP: netip.MustParseAddr("1.1.1.1"), Protocol: "ICMP"}
	w5 := TargetWorker{Host: "example.com", Protocol: "DNS"}

	for _, w := range []TargetWorker{w1, w2, w3, w4, w5} {
		assert.NotEmpty(t, formatTargetBadge(w))
		assert.NotEmpty(t, formatTargetBadgeColored(w))
	}
}

func TestTCP_Address(t *testing.T) {
	p := NewTcping(TCPOptions{
		Hostname: "example.com",
		IP:       netip.MustParseAddr("93.184.216.34"),
		Port:     80,
	})
	assert.Equal(t, "93.184.216.34:80", p.address())

	p2 := NewTcping(TCPOptions{
		Hostname: "example.com",
		Port:     80,
	})
	assert.Equal(t, "example.com:80", p2.address())
}

func TestExtractTNSParam(t *testing.T) {
	tnsStr := "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db.local)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=orcl)))"
	assert.Equal(t, "=TCP", extractTNSParam(tnsStr, "PROTOCOL"))
	assert.Equal(t, "=orcl", extractTNSParam(tnsStr, "SERVICE_NAME"))
	assert.Equal(t, "", extractTNSParam(tnsStr, "NONEXISTENT"))
}

func TestHana_VersionDecoders(t *testing.T) {
	assert.Equal(t, "SAP HANA 2.0 SPS05 (2.00.050.00)", decodeHanaVersion("2.00.050.00"))
	assert.Equal(t, "SAP HANA 2.0 SPS05 Patch 2 (2.00.052.00)", decodeHanaVersion("2.00.052.00"))
	assert.Equal(t, "SAP HANA 1.00", decodeHanaVersion("1.00"))
}

func TestBSON_Extractors(t *testing.T) {
	// Construct a small BSON document buffer
	var buf bytes.Buffer
	// String element (0x02), key="version\x00", len=6, "5.0.0\x00"
	buf.WriteByte(0x02)
	buf.WriteString("version\x00")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(6))
	buf.WriteString("5.0.0\x00")

	// Int32 element (0x10), key="maxBsonObjectSize\x00", value=16777216
	buf.WriteByte(0x10)
	buf.WriteString("maxBsonObjectSize\x00")
	_ = binary.Write(&buf, binary.LittleEndian, int32(16777216))

	// Int64 element (0x12), key="ok\x00", value=1
	buf.WriteByte(0x12)
	buf.WriteString("ok\x00")
	_ = binary.Write(&buf, binary.LittleEndian, int64(1))

	// Bool element (0x08), key="isWritablePrimary\x00", value=1
	buf.WriteByte(0x08)
	buf.WriteString("isWritablePrimary\x00")
	buf.WriteByte(0x01)

	raw := buf.Bytes()
	assert.Equal(t, "5.0.0", extractBSONString(raw, "version"))
	assert.Equal(t, int32(16777216), extractBSONInt32(raw, "maxBsonObjectSize"))
	assert.Equal(t, int64(1), extractBSONInt64(raw, "ok"))
	assert.True(t, extractBSONBool(raw, "isWritablePrimary"))

	assert.Equal(t, "", extractBSONString(raw, "nonexistent"))
	assert.Equal(t, int32(-1), extractBSONInt32(raw, "nonexistent"))
	assert.Equal(t, int64(-1), extractBSONInt64(raw, "nonexistent"))
	assert.False(t, extractBSONBool(raw, "nonexistent"))
}

func TestFTP_ReadResponse_Multiline(t *testing.T) {
	banner := "220-Welcome to Pure-FTPd\r\n220-You are user number 1 of 50 allowed.\r\n220 This is a private system\r\n"
	reader := bufio.NewReader(strings.NewReader(banner))
	lastLine, lines, err := readFTPResponse(reader)
	assert.NoError(t, err)
	assert.Equal(t, "220 This is a private system", lastLine)
	assert.Equal(t, 3, len(lines))
	assert.Contains(t, lines[0], "Pure-FTPd")
}

func TestDNSQuery_BuildAndParseName(t *testing.T) {
	pkt := buildDNSQuery("example.com")
	assert.NotEmpty(t, pkt)

	name, offset, err := parseDNSName(pkt, 12)
	assert.NoError(t, err)
	assert.Equal(t, "example.com", name)
	assert.True(t, offset > 12)
}

func TestSSH_FormatTopItems(t *testing.T) {
	items := "aes128-gcm,aes256-gcm,chacha20-poly1305,aes128-ctr"
	formatted := formatTopItems(items, 2)
	assert.Equal(t, "aes128-gcm|aes256-gcm", formatted)

	var buf bytes.Buffer
	// SSH namelist binary format: 4-byte length + comma-separated strings
	namelist := "curve25519-sha256,ecdh-sha2-nistp256"
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(namelist)))
	buf.WriteString(namelist)
	parsedStr, err := readSSHNameList(&buf)
	assert.NoError(t, err)
	assert.Contains(t, parsedStr, "curve25519-sha256")
}

func TestProber_Constructors_AllProtocols(t *testing.T) {
	targetIP := netip.MustParseAddr("127.0.0.1")

	o365P := NewO365ing(O365Options{
		Hostname: "outlook.office365.com",
		IP:       targetIP,
		Port:     443,
		Timeout:  time.Second,
	})
	assert.NotNil(t, o365P)

	qP1 := NewQueueing(QueueOptions{
		Protocol: QueueKafka,
		Hostname: "kafka.local",
		IP:       targetIP,
		Port:     9092,
		Timeout:  time.Second,
	})
	assert.NotNil(t, qP1)

	qP2 := NewQueueing(QueueOptions{
		Protocol: QueueRabbitMQ,
		Hostname: "rabbit.local",
		IP:       targetIP,
		Port:     5672,
		Timeout:  time.Second,
	})
	assert.NotNil(t, qP2)

	sP := NewStorageing(StorageOptions{
		Type:     StorageS3,
		Hostname: "s3.amazonaws.com",
		IP:       targetIP,
		Port:     443,
		Timeout:  time.Second,
	})
	assert.NotNil(t, sP)

	wsP := NewWSing(WSOptions{
		Hostname: "stream.binance.com",
		IP:       targetIP,
		Port:     9443,
		UseTLS:   true,
		Timeout:  time.Second,
	})
	assert.NotNil(t, wsP)

	mP1 := NewMailing(MailOptions{
		Protocol: MailSMTP,
		Hostname: "smtp.gmail.com",
		IP:       targetIP,
		Port:     587,
		StartTLS: true,
		Timeout:  time.Second,
	})
	assert.NotNil(t, mP1)

	mP2 := NewMailing(MailOptions{
		Protocol: MailIMAP,
		Hostname: "imap.gmail.com",
		IP:       targetIP,
		Port:     993,
		UseTLS:   true,
		Timeout:  time.Second,
	})
	assert.NotNil(t, mP2)

	mP3 := NewMailing(MailOptions{
		Protocol: MailPOP3,
		Hostname: "pop.gmail.com",
		IP:       targetIP,
		Port:     995,
		UseTLS:   true,
		Timeout:  time.Second,
	})
	assert.NotNil(t, mP3)
}

func TestDNSQuery_DissectResponse_ShortPacket(t *testing.T) {
	_, err := dissectDNSResponse([]byte{0x00, 0x01, 0x81})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestDNSQuery_DissectResponse_Codes(t *testing.T) {
	// Construct a standard 12-byte header with flags
	makeHeader := func(flags uint16) []byte {
		hdr := make([]byte, 12)
		binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
		binary.BigEndian.PutUint16(hdr[2:4], flags)
		return hdr
	}

	// NOERROR (rcode = 0, QR=1, AA=1, RD=1, RA=1 -> 0x8580)
	r1, err := dissectDNSResponse(makeHeader(0x8580))
	assert.NoError(t, err)
	assert.Equal(t, "NOERROR", r1.RcodeStr)
	assert.Contains(t, r1.Flags, "AA")
	assert.Contains(t, r1.Flags, "RD")
	assert.Contains(t, r1.Flags, "RA")

	// SERVFAIL (rcode = 2 -> 0x8002)
	r2, err := dissectDNSResponse(makeHeader(0x8002))
	assert.NoError(t, err)
	assert.Equal(t, "SERVFAIL", r2.RcodeStr)

	// NXDOMAIN (rcode = 3 -> 0x8003)
	r3, err := dissectDNSResponse(makeHeader(0x8003))
	assert.NoError(t, err)
	assert.Equal(t, "NXDOMAIN", r3.RcodeStr)

	// FORMERR (rcode = 1 -> 0x8001)
	r4, err := dissectDNSResponse(makeHeader(0x8001))
	assert.NoError(t, err)
	assert.Equal(t, "FORMERR", r4.RcodeStr)

	// REFUSED (rcode = 5 -> 0x8005)
	r5, err := dissectDNSResponse(makeHeader(0x8005))
	assert.NoError(t, err)
	assert.Equal(t, "REFUSED", r5.RcodeStr)
}

func TestDNSQuery_ParseDNSName_Errors(t *testing.T) {
	_, _, err := parseDNSName([]byte{}, 0)
	assert.Error(t, err)

	_, _, err = parseDNSName([]byte{0xc0}, 0)
	assert.Error(t, err)

	_, _, err = parseDNSName([]byte{0x05, 'a', 'b'}, 0)
	assert.Error(t, err)
}

func TestDNSQuery_DissectResponse_WithAnswers(t *testing.T) {
	// Build packet: Header (12 bytes, qdCount=1, anCount=3) + Question (example.com + Type 1 + Class 1) + Answer 1 (A: 1.2.3.4) + Answer 2 (AAAA: ::1) + Answer 3 (CNAME)
	var pkt bytes.Buffer
	// Header: ID=0x1234, Flags=0x8180 (NOERROR, QR=1, RD=1, RA=1), QDCOUNT=1, ANCOUNT=3, NSCOUNT=0, ARCOUNT=0
	_ = binary.Write(&pkt, binary.BigEndian, uint16(0x1234))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(0x8180))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1)) // QD
	_ = binary.Write(&pkt, binary.BigEndian, uint16(3)) // AN
	_ = binary.Write(&pkt, binary.BigEndian, uint16(0))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(0))

	// Question: \x07example\x03com\x00 Type=1 (A), Class=1 (IN)
	pkt.Write([]byte("\x07example\x03com\x00"))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))

	// Answer 1: Name ptr -> offset 12 (0xc00c), Type 1 (A), Class 1, TTL 300, RdLength 4, IP 1.2.3.4
	_ = binary.Write(&pkt, binary.BigEndian, uint16(0xc00c))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
	_ = binary.Write(&pkt, binary.BigEndian, uint32(300))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(4))
	pkt.Write([]byte{1, 2, 3, 4})

	// Answer 2: Name ptr -> offset 12 (0xc00c), Type 28 (AAAA), Class 1, TTL 600, RdLength 16, IP ::1
	_ = binary.Write(&pkt, binary.BigEndian, uint16(0xc00c))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(28))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
	_ = binary.Write(&pkt, binary.BigEndian, uint32(600))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(16))
	pkt.Write(net.ParseIP("::1").To16())

	// Answer 3: Name ptr -> offset 12 (0xc00c), Type 5 (CNAME), Class 1, TTL 900, RdLength 11, target ptr -> offset 12
	_ = binary.Write(&pkt, binary.BigEndian, uint16(0xc00c))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(5))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
	_ = binary.Write(&pkt, binary.BigEndian, uint32(900))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(2))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(0xc00c))

	resp, err := dissectDNSResponse(pkt.Bytes())
	assert.NoError(t, err)
	assert.Equal(t, "NOERROR", resp.RcodeStr)
	assert.Equal(t, 3, len(resp.Answers))
	assert.Equal(t, "1.2.3.4", resp.Answers[0])
	assert.Equal(t, "::1", resp.Answers[1])
	assert.Equal(t, "CNAME->example.com", resp.Answers[2])
	assert.Equal(t, uint32(300), resp.MinTTL)
}

func TestStorage_Ping_Mock(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-amz-request-id", "mock-s3-req-12345")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<Error><Code>AccessDenied</Code></Error>"))
	}))
	defer ts.Close()

	sP := NewStorageing(StorageOptions{
		Type:     StorageS3,
		Hostname: "127.0.0.1",
		Port:     80,
		Timeout:  time.Second,
	})
	sP.httpClient = ts.Client()
	sP.url = ts.URL

	res := sP.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, 403, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "HTTP 403")

	// Test Azure Blob header
	tsAzure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "2023-08-03", r.Header.Get("x-ms-version"))
		w.Header().Set("x-ms-request-id", "azure-blob-req-67890")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer tsAzure.Close()

	azureP := NewStorageing(StorageOptions{
		Type:     StorageAzureBlob,
		Hostname: "127.0.0.1",
		Port:     80,
		Timeout:  time.Second,
	})
	azureP.httpClient = tsAzure.Client()
	azureP.url = tsAzure.URL

	resAzure := azureP.Ping(context.Background())
	assert.NoError(t, resAzure.Err)
	assert.Equal(t, 403, resAzure.HTTPStatus)
}

func TestProber_FinalizeStatistics_Down(t *testing.T) {
	st := stats.NewStatistics(stats.Options{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     80,
	})
	st.StartTime = time.Now().Add(-10 * time.Second)
	st.DestWasDown = true
	st.StartOfDowntime = time.Now().Add(-5 * time.Second)

	p := &Prober{
		Statistics: st,
	}
	p.finalizeStatistics()

	assert.True(t, st.TotalDowntime > 0)
	assert.True(t, st.UpTime > 0)
}

func TestQueue_Kafka_Mock(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Write response first so client never hangs waiting for server
		resp := []byte{
			0x00, 0x00, 0x00, 0x0A,
			0x00, 0x00, 0x00, 0x01,
			0x00, 0x00,
			0x00, 0x00, 0x00, 0x05,
		}
		_, _ = conn.Write(resp)

		buf := make([]byte, 23)
		_, _ = io.ReadFull(conn, buf)
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	q := NewQueueing(QueueOptions{
		Protocol: QueueKafka,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := q.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "Kafka: ApiVersions OK")
}

func TestQueue_RabbitMQ_Mock(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Write AMQP Connection.Start frame first
		resp := []byte{
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C,
			0x00, 0x0A, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0xCE,
		}
		_, _ = conn.Write(resp)

		buf := make([]byte, 8)
		_, _ = io.ReadFull(conn, buf)
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	q := NewQueueing(QueueOptions{
		Protocol: QueueRabbitMQ,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := q.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "AMQP 0-9-1")
}

func TestRedis_MockPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		r := bufio.NewReader(conn)
		// Read PING
		_, _ = r.ReadString('\n')
		_, _ = r.ReadString('\n')
		_, _ = conn.Write([]byte("+PONG\r\n"))

		// Read INFO
		_, _ = r.ReadString('\n')
		_, _ = r.ReadString('\n')
		_, _ = r.ReadString('\n')
		_, _ = r.ReadString('\n')
		infoResp := "$30\r\nredis_version:7.2.4\r\nuptime:100\r\n"
		_, _ = conn.Write([]byte(infoResp))
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	red := NewRedising(RedisOptions{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := red.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "7.2.4")
}

func TestMemcached_MockPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		r := bufio.NewReader(conn)
		// Read version command
		_, _ = r.ReadString('\n')
		_, _ = conn.Write([]byte("VERSION 1.6.22\r\n"))

		// Read stats command
		_, _ = r.ReadString('\n')
		resp := "STAT curr_items 42\r\nSTAT total_connections 100\r\nEND\r\n"
		_, _ = conn.Write([]byte(resp))
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	mc := NewMemcacheding(MemcachedOptions{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := mc.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "1.6.22")
}

func TestPostgres_MockPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read SSLRequest (8 bytes)
		sslReq := make([]byte, 8)
		_, _ = io.ReadFull(conn, sslReq)
		// Send 'N' (no SSL)
		_, _ = conn.Write([]byte("N"))

		// Read StartupMessage
		lenBuf := make([]byte, 4)
		_, _ = io.ReadFull(conn, lenBuf)
		pktLen := int(binary.BigEndian.Uint32(lenBuf))
		if pktLen > 4 {
			rest := make([]byte, pktLen-4)
			_, _ = io.ReadFull(conn, rest)
		}

		// Send Auth Cleartext reply ('R' + 4 bytes len + 4 bytes auth type 3)
		authResp := []byte{
			'R',
			0x00, 0x00, 0x00, 0x08,
			0x00, 0x00, 0x00, 0x03,
		}
		_, _ = conn.Write(authResp)
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	db := NewDBing(DBOptions{
		Type:     PostgreSQL,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "SSL: Not Supported")
}

func TestMySQL_MockPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// MySQL Handshake error packet
		errMsg := "Access denied for user 'netping'@'127.0.0.1'"
		pktLen := 1 + 2 + len(errMsg)
		resp := append([]byte{
			byte(pktLen), 0x00, 0x00, 0x00, // 3-byte len + seq=0
			0xff,       // Error byte
			0x15, 0x04, // Error code 1045
		}, []byte(errMsg)...)
		_, _ = conn.Write(resp)
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	db := NewDBing(DBOptions{
		Type:     MySQL,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "Error: #1045")
}

func TestMail_SMTP_MockPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		r := bufio.NewReader(conn)
		// Send 220 banner
		_, _ = conn.Write([]byte("220 smtp.local ESMTP Postfix\r\n"))
		// Read EHLO
		_, _ = r.ReadString('\n')
		// Send 250 capabilities
		_, _ = conn.Write([]byte("250-smtp.local\r\n250-SIZE 52428800\r\n250 HELP\r\n"))
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	m := NewMailing(MailOptions{
		Protocol: MailSMTP,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := m.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "ESMTP Postfix")
}

func TestMail_IMAP_MockPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		r := bufio.NewReader(conn)
		// Send IMAP banner
		_, _ = conn.Write([]byte("* OK IMAP4rev1 Service Ready\r\n"))
		// Read CAPABILITY command
		_, _ = r.ReadString('\n')
		// Send capabilities
		_, _ = conn.Write([]byte("* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\nA001 OK Completed\r\n"))
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	m := NewMailing(MailOptions{
		Protocol: MailIMAP,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := m.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "IMAP4rev1")
}

func TestMail_POP3_MockPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		r := bufio.NewReader(conn)
		// Send POP3 banner
		_, _ = conn.Write([]byte("+OK POP3 server ready\r\n"))
		// Read CAPA command
		_, _ = r.ReadString('\n')
		// Send capabilities
		_, _ = conn.Write([]byte("+OK Capability list follows\r\nTOP\r\nUSER\r\n.\r\n"))
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	m := NewMailing(MailOptions{
		Protocol: MailPOP3,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := m.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "POP3 server ready")
}

func TestCassandra_MockPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read STARTUP frame (22 bytes)
		buf := make([]byte, 22)
		_, _ = io.ReadFull(conn, buf)

		// Send READY response (9 bytes header: version 0x84, stream 1, opcode 0x02 READY)
		resp := []byte{0x84, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00}
		_, _ = conn.Write(resp)
		time.Sleep(50 * time.Millisecond)
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	db := NewDBing(DBOptions{
		Type:     Cassandra,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "READY")
}

func TestMSSQL_MockPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read PRELOGIN (32 bytes)
		buf := make([]byte, 32)
		_, _ = io.ReadFull(conn, buf)

		// Send TDS response (8 bytes header + token terminator)
		resp := []byte{
			0x04, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, // Header: type 4, length 16
			0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Body
		}
		_, _ = conn.Write(resp)
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	db := NewDBing(DBOptions{
		Type:     MSSQL,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
}

func TestFTP_MockPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		r := bufio.NewReader(conn)
		// 220 banner
		_, _ = conn.Write([]byte("220 FTP Server ready\r\n"))

		// Read FEAT
		_, _ = r.ReadString('\n')
		_, _ = conn.Write([]byte("211-Features:\r\n UTF8\r\n211 End\r\n"))

		// Read QUIT
		_, _ = r.ReadString('\n')
		_, _ = conn.Write([]byte("221 Goodbye\r\n"))
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	ftp := NewFTPing(FTPOptions{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := ftp.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "FTP Server ready")
}

func TestWS_MockPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		r := bufio.NewReader(conn)
		// Read HTTP Upgrade request until empty line
		for {
			line, err := r.ReadString('\n')
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
		}

		// Write 101 Switching Protocols response
		upgradeResp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
		_, _ = conn.Write([]byte(upgradeResp))

		// Read Ping frame (6 bytes header + payload)
		buf := make([]byte, 10)
		_, _ = io.ReadFull(conn, buf)

		// Write Pong frame
		pongFrame := []byte{0x8a, 0x04, buf[6], buf[7], buf[8], buf[9]}
		_, _ = conn.Write(pongFrame)
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	ws := NewWSing(WSOptions{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := ws.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "101 Switching Protocols")
}

func TestLDAP_MockPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read BindRequest (14 bytes)
		buf := make([]byte, 14)
		_, _ = io.ReadFull(conn, buf)

		// Send BindResponse (SUCCESS, code 0)
		resp := []byte{0x30, 0x0C, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
		_, _ = conn.Write(resp)
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	ldapP := NewLDAPing(LDAPOptions{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := ldapP.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "Bind: SUCCESS")
}

func TestRsync_MockPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		r := bufio.NewReader(conn)
		// Send server greeting
		_, _ = conn.Write([]byte("@RSYNCD: 31.0\n"))

		// Read client greeting
		_, _ = r.ReadString('\n')

		// Read empty line
		_, _ = r.ReadString('\n')

		// Send modules list and exit
		_, _ = conn.Write([]byte("pub\tPublic mirror\n@RSYNCD: EXIT\n"))
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	rsyncP := NewRsyncing(RsyncOptions{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := rsyncP.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "31.0")
}

func TestLDAP_ExtractStringAttr(t *testing.T) {
	// Construct simulated ASN.1 buffer with "vendorName" + OCTET STRING "OpenLDAP"
	data := append([]byte("vendorName"), 0x04, 0x08)
	data = append(data, []byte("OpenLDAP")...)
	assert.Equal(t, "OpenLDAP", extractLDAPStringAttr(data, "vendorName"))
	assert.Equal(t, "", extractLDAPStringAttr(data, "nonexistent"))
}

func TestTCP_Ping_SendData_ExpectData(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		_, _ = io.ReadFull(conn, buf)
		if string(buf) == "PING" {
			_, _ = conn.Write([]byte("PONG_OK"))
		}
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	p := NewTcping(TCPOptions{
		Hostname:   "127.0.0.1",
		IP:         netip.MustParseAddr("127.0.0.1"),
		Port:       uint16(tcpAddr.Port),
		SendData:   "PING",
		ExpectData: "PONG",
		Timeout:    3 * time.Second,
	})

	res := p.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "Payload Matched")
}

func TestUDP_Ping_SendData_ExpectData(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	assert.NoError(t, err)
	defer conn.Close()

	go func() {
		buf := make([]byte, 1024)
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err == nil && n > 0 {
			_, _ = conn.WriteToUDP([]byte("HEARTBEAT_ACK"), remoteAddr)
		}
	}()

	lAddr := conn.LocalAddr().(*net.UDPAddr)
	p := NewUDPing(UDPOptions{
		IP:         netip.MustParseAddr("127.0.0.1"),
		Port:       uint16(lAddr.Port),
		SendData:   "HEARTBEAT",
		ExpectData: "ACK",
		Timeout:    3 * time.Second,
	})

	res := p.Ping(context.Background())
	assert.NoError(t, res.Err)
}

func TestCassandra_Authenticate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read STARTUP
		buf := make([]byte, 22)
		_, _ = io.ReadFull(conn, buf)

		// AUTHENTICATE response: opcode 0x03, body length 28 (class: org.apache.cassandra.auth.PasswordAuthenticator)
		authClass := "org.apache.cassandra.auth.PasswordAuthenticator"
		body := append([]byte{0x00, byte(len(authClass))}, []byte(authClass)...)
		header := []byte{0x84, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, byte(len(body))}
		_, _ = conn.Write(append(header, body...))
		time.Sleep(50 * time.Millisecond)
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	db := NewDBing(DBOptions{
		Type:     Cassandra,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "PasswordAuthenticator")
}

func TestMongoDB_MockPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Build BSON document: version string "7.0.5"
		var doc bytes.Buffer
		doc.WriteByte(0x02) // string
		doc.WriteString("version\x00")
		_ = binary.Write(&doc, binary.LittleEndian, uint32(6))
		doc.WriteString("7.0.5\x00")
		doc.WriteByte(0x00) // null terminator

		docBytes := doc.Bytes()
		totalDocLen := uint32(len(docBytes) + 4)
		fullDoc := append([]byte{byte(totalDocLen), byte(totalDocLen >> 8), byte(totalDocLen >> 16), byte(totalDocLen >> 24)}, docBytes...)

		// OP_MSG body: 4 bytes flagBits + 1 byte sectionKind + fullDoc
		body := append([]byte{0x00, 0x00, 0x00, 0x00, 0x00}, fullDoc...)
		totalMsgLen := uint32(len(body) + 16)
		header := []byte{
			byte(totalMsgLen), byte(totalMsgLen >> 8), byte(totalMsgLen >> 16), byte(totalMsgLen >> 24),
			0x02, 0x00, 0x00, 0x00, // RequestID 2
			0x01, 0x00, 0x00, 0x00, // ResponseTo 1
			0xdd, 0x07, 0x00, 0x00, // OpCode OP_MSG
		}
		_, _ = conn.Write(append(header, body...))

		// Read client request
		buf := make([]byte, 52)
		_, _ = io.ReadFull(conn, buf)
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	db := NewDBing(DBOptions{
		Type:     MongoDB,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "7.0.5")
}

func TestOracle_MockPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read client connect
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)

		// Send TNS ACCEPT packet (length 16, type 2)
		tnsAccept := []byte{
			0x00, 0x10, 0x00, 0x00, // Length 16
			0x02,             // Type 2: ACCEPT
			0x00, 0x00, 0x00, // Reserved
			0x01, 0x3c, 0x01, 0x2c, // Version 316, Compatible 300
			0x00, 0x00, 0x00, 0x00, // Options
		}
		_, _ = conn.Write(tnsAccept)
		time.Sleep(50 * time.Millisecond)
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	db := NewDBing(DBOptions{
		Type:     Oracle,
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     uint16(tcpAddr.Port),
		Timeout:  3 * time.Second,
	})

	res := db.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "TNS: ACCEPT")
}

func TestProbers_Constructors_MailTLS(t *testing.T) {
	targetIP := netip.MustParseAddr("127.0.0.1")

	// SMTP without TLS
	s1 := NewMailing(MailOptions{Protocol: MailSMTP, IP: targetIP})
	assert.Equal(t, uint16(25), s1.port)

	// SMTP with TLS
	s2 := NewMailing(MailOptions{Protocol: MailSMTP, IP: targetIP, UseTLS: true})
	assert.Equal(t, uint16(465), s2.port)

	// IMAP without TLS
	i1 := NewMailing(MailOptions{Protocol: MailIMAP, IP: targetIP})
	assert.Equal(t, uint16(143), i1.port)

	// POP3 without TLS
	p1 := NewMailing(MailOptions{Protocol: MailPOP3, IP: targetIP})
	assert.Equal(t, uint16(110), p1.port)
}

func TestOracle_DecodeVSN_Full(t *testing.T) {
	// Error case
	assert.Equal(t, "", decodeOracleVSN("invalid"))

	// Major versions
	makeVSN := func(major uint32) string {
		val := major << 24
		return strconv.FormatUint(uint64(val), 10)
	}

	assert.Contains(t, decodeOracleVSN(makeVSN(23)), "Oracle 23c")
	assert.Contains(t, decodeOracleVSN(makeVSN(21)), "Oracle 21c")
	assert.Contains(t, decodeOracleVSN(makeVSN(19)), "Oracle 19c")
	assert.Contains(t, decodeOracleVSN(makeVSN(18)), "Oracle 18c")
	assert.Contains(t, decodeOracleVSN(makeVSN(12)), "Oracle 12c")
	assert.Contains(t, decodeOracleVSN(makeVSN(11)), "Oracle 11g")
	assert.Contains(t, decodeOracleVSN(makeVSN(10)), "Oracle v10")
}

func TestNewProber_Defaults(t *testing.T) {
	st := stats.NewStatistics(stats.Options{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     80,
	})
	p := NewProber(nil, nil, st, Options{
		IntervalBetweenProbes: 0,
		Timeout:               0,
	})
	assert.NotNil(t, p)
	assert.Equal(t, time.Second, p.Timeout)
	p.Ticker.Stop()
}

func TestTNSProtocolRelease_Full(t *testing.T) {
	assert.Equal(t, "Oracle 19c/21c/23c", tnsProtocolRelease(316))
	assert.Equal(t, "Oracle 18c", tnsProtocolRelease(315))
	assert.Equal(t, "Oracle 12c R2", tnsProtocolRelease(314))
	assert.Equal(t, "Oracle 12c R1", tnsProtocolRelease(313))
	assert.Equal(t, "Oracle 11g R2", tnsProtocolRelease(312))
	assert.Equal(t, "Oracle 11g R1", tnsProtocolRelease(311))
	assert.Equal(t, "Oracle 10g", tnsProtocolRelease(310))
	assert.Equal(t, "Oracle TNS v300", tnsProtocolRelease(300))
}

func TestMongoDB_BSON_WireVersions(t *testing.T) {
	// Construct doc with maxWireVersion
	makeWireDoc := func(wire int32) []byte {
		var doc bytes.Buffer
		doc.WriteByte(0x10) // int32
		doc.WriteString("maxWireVersion\x00")
		_ = binary.Write(&doc, binary.LittleEndian, wire)
		doc.WriteByte(0x00) // terminator
		docBytes := doc.Bytes()
		docLen := uint32(len(docBytes) + 4)
		return append([]byte{byte(docLen), byte(docLen >> 8), byte(docLen >> 16), byte(docLen >> 24)}, docBytes...)
	}

	assert.Equal(t, int32(25), extractBSONInt32(makeWireDoc(25), "maxWireVersion"))
	assert.Equal(t, int32(21), extractBSONInt32(makeWireDoc(21), "maxWireVersion"))
	assert.Equal(t, int32(17), extractBSONInt32(makeWireDoc(17), "maxWireVersion"))
	assert.Equal(t, int32(13), extractBSONInt32(makeWireDoc(13), "maxWireVersion"))
	assert.Equal(t, int32(9), extractBSONInt32(makeWireDoc(9), "maxWireVersion"))
}

func TestRedis_ReadRESPBulkString_Branches(t *testing.T) {
	// Nil bulk string
	str, err := readRESPBulkString(bufio.NewReader(strings.NewReader("")), "$-1")
	assert.NoError(t, err)
	assert.Equal(t, "", str)

	// Valid bulk string
	str2, err := readRESPBulkString(bufio.NewReader(strings.NewReader("hello\r\n")), "$5")
	assert.NoError(t, err)
	assert.Equal(t, "hello", str2)

	// Invalid length
	_, err = readRESPBulkString(bufio.NewReader(strings.NewReader("")), "$abc")
	assert.Error(t, err)

	// Truncated data
	_, err = readRESPBulkString(bufio.NewReader(strings.NewReader("he")), "$5")
	assert.Error(t, err)
}

func TestOracle_Refuse_Redirect(t *testing.T) {
	// Test REFUSE packet
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln1.Close()

	go func() {
		conn, err := ln1.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 512)
		_, _ = conn.Read(buf)

		refuseBody := "(DESCRIPTION=(ERR=12514)(VSN=353894400))"
		pktLen := uint16(len(refuseBody) + 8)
		hdr := make([]byte, 8)
		binary.BigEndian.PutUint16(hdr[0:2], pktLen)
		hdr[4] = 0x04 // REFUSE
		_, _ = conn.Write(append(hdr, []byte(refuseBody)...))
		time.Sleep(50 * time.Millisecond)
	}()

	tcpAddr1 := ln1.Addr().(*net.TCPAddr)
	db1 := NewDBing(DBOptions{
		Type:        Oracle,
		Hostname:    "127.0.0.1",
		IP:          netip.MustParseAddr("127.0.0.1"),
		Port:        uint16(tcpAddr1.Port),
		ServiceName: "XE",
		Timeout:     3 * time.Second,
	})

	res1 := db1.Ping(context.Background())
	assert.NoError(t, res1.Err)
	assert.Contains(t, res1.Diagnostics, "TNS-12514")

	// Test REDIRECT packet
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln2.Close()

	go func() {
		conn, err := ln2.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 512)
		_, _ = conn.Read(buf)

		hdr := make([]byte, 8)
		binary.BigEndian.PutUint16(hdr[0:2], 8)
		hdr[4] = 0x05 // REDIRECT
		_, _ = conn.Write(hdr)
		time.Sleep(50 * time.Millisecond)
	}()

	tcpAddr2 := ln2.Addr().(*net.TCPAddr)
	db2 := NewDBing(DBOptions{
		Type:        Oracle,
		Hostname:    "127.0.0.1",
		IP:          netip.MustParseAddr("127.0.0.1"),
		Port:        uint16(tcpAddr2.Port),
		ServiceName: "XE",
		Timeout:     3 * time.Second,
	})

	res2 := db2.Ping(context.Background())
	assert.NoError(t, res2.Err)
	assert.Contains(t, res2.Diagnostics, "REDIRECT")
}
