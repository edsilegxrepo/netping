package config

import (
	"testing"

	"github.com/edsilegx/netping/pkg/consts"
	"github.com/stretchr/testify/assert"
)

func TestParseHostPortArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantHost string
		wantPort string
	}{
		{
			name:     "traditional format: host port",
			args:     []string{"example.com", "8080"},
			wantHost: "example.com",
			wantPort: "8080",
		},
		{
			name:     "host:port format",
			args:     []string{"example.com:8080"},
			wantHost: "example.com",
			wantPort: "8080",
		},
		{
			name:     "IPv4:port format",
			args:     []string{"192.168.1.1:443"},
			wantHost: "192.168.1.1",
			wantPort: "443",
		},
		{
			name:     "IPv6 with brackets and port",
			args:     []string{"[2001:db8::1]:8080"},
			wantHost: "2001:db8::1",
			wantPort: "8080",
		},
		{
			name:     "IPv6 without brackets and port is ambiguous, returned as-is",
			args:     []string{"2001:db8::1:8080"},
			wantHost: "2001:db8::1:8080",
			wantPort: "",
		},
		{
			name:     "localhost:port format",
			args:     []string{"localhost:80"},
			wantHost: "localhost",
			wantPort: "80",
		},
		{
			name:     "IPv6 localhost with brackets",
			args:     []string{"[::1]:22"},
			wantHost: "::1",
			wantPort: "22",
		},
		{
			name:     "IPv6 localhost without brackets is ambiguous, returned as-is",
			args:     []string{"::1:22"},
			wantHost: "::1:22",
			wantPort: "",
		},
		{
			name:     "single argument without colon",
			args:     []string{"example.com"},
			wantHost: "example.com",
			wantPort: "",
		},
		{
			name:     "three arguments: only first two are used",
			args:     []string{"example.com", "8080", "extra"},
			wantHost: "example.com",
			wantPort: "8080",
		},
		{
			name:     "empty string argument",
			args:     []string{""},
			wantHost: "",
			wantPort: "",
		},
		{
			name:     "host:port with empty port",
			args:     []string{"example.com:"},
			wantHost: "example.com",
			wantPort: "",
		},
		{
			name:     "host:port with empty host",
			args:     []string{":8080"},
			wantHost: "",
			wantPort: "8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, gotPort := parseHostPortArgs(tt.args)
			if gotHost != tt.wantHost || gotPort != tt.wantPort {
				t.Errorf("parseHostPortArgs(%v) = (%q, %q), want (%q, %q)",
					tt.args, gotHost, gotPort, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name string
		v1   string
		v2   string
		want int
	}{
		{
			name: "equal versions",
			v1:   "1.2.3",
			v2:   "1.2.3",
			want: 0,
		},
		{
			name: "v1 major less than v2",
			v1:   "1.2.3",
			v2:   "2.0.0",
			want: -1,
		},
		{
			name: "v1 major greater than v2",
			v1:   "3.0.0",
			v2:   "2.9.9",
			want: 1,
		},
		{
			name: "v1 minor less than v2",
			v1:   "1.2.3",
			v2:   "1.3.0",
			want: -1,
		},
		{
			name: "v1 minor greater than v2",
			v1:   "1.4.0",
			v2:   "1.3.9",
			want: 1,
		},
		{
			name: "v1 patch less than v2",
			v1:   "1.2.3",
			v2:   "1.2.4",
			want: -1,
		},
		{
			name: "v1 patch greater than v2",
			v1:   "1.2.5",
			v2:   "1.2.4",
			want: 1,
		},
		{
			name: "v1 shorter but equal in common parts",
			v1:   "1.2",
			v2:   "1.2.0",
			want: -1,
		},
		{
			name: "v1 longer but equal in common parts",
			v1:   "1.2.0",
			v2:   "1.2",
			want: 1,
		},
		{
			name: "v1 shorter and less in common parts",
			v1:   "1.2",
			v2:   "1.3.0",
			want: -1,
		},
		{
			name: "v1 longer and greater in common parts",
			v1:   "2.0.0",
			v2:   "1.9",
			want: 1,
		},
		{
			name: "single-digit versions equal",
			v1:   "1",
			v2:   "1",
			want: 0,
		},
		{
			name: "non-numeric segment treated as zero",
			v1:   "1.x.0",
			v2:   "1.0.0",
			want: 0,
		},
		{
			name: "both empty strings",
			v1:   "",
			v2:   "",
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVersions(tt.v1, tt.v2)
			if got != tt.want {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

func TestParseHostPort(t *testing.T) {
	h, p := ParseHostPort("example.com:8080", 80)
	if h != "example.com" || p != 8080 {
		t.Errorf("expected example.com:8080, got %s:%d", h, p)
	}

	h, p = ParseHostPort("example.com", 443)
	if h != "example.com" || p != 443 {
		t.Errorf("expected example.com:443, got %s:%d", h, p)
	}

	h, p = ParseHostPort("example.com:invalid", 80)
	if h != "example.com" || p != 80 {
		t.Errorf("expected example.com:80, got %s:%d", h, p)
	}
}

func TestConvertAndValidatePort(t *testing.T) {
	p, err := convertAndValidatePort("8080")
	if err != nil || p != 8080 {
		t.Errorf("expected 8080, got %d, err: %v", p, err)
	}

	_, err = convertAndValidatePort("0")
	if err == nil {
		t.Errorf("expected error for port 0")
	}

	_, err = convertAndValidatePort("70000")
	if err == nil {
		t.Errorf("expected error for port 70000")
	}

	_, err = convertAndValidatePort("invalid")
	if err == nil {
		t.Errorf("expected error for invalid port")
	}
}

func TestResolveTargetPool(t *testing.T) {
	// 1. Single target (host + port)
	t1, err := ResolveTargetPool("1.1.1.1", "443", "", "tcp", "")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(t1))
	assert.Equal(t, "1.1.1.1", t1[0].Host)
	assert.Equal(t, uint16(443), t1[0].Port)

	// 2. Single target (URI)
	t2, err := ResolveTargetPool("", "", "1.1.1.1:8443", "https", "")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(t2))
	assert.Equal(t, "1.1.1.1", t2[0].Host)
	assert.Equal(t, uint16(8443), t2[0].Port)

	// 3. Multi-host sweep (single port)
	t3, err := ResolveTargetPool("web1, web2, web3", "443", "", "https", "")
	assert.NoError(t, err)
	assert.Equal(t, 3, len(t3))
	assert.Equal(t, "web1", t3[0].Host)
	assert.Equal(t, "web2", t3[1].Host)
	assert.Equal(t, "web3", t3[2].Host)
	assert.Equal(t, uint16(443), t3[0].Port)

	// 4. Multi-port sweep (single host)
	t4, err := ResolveTargetPool("db1", "1433, 5432, 3306", "", "tcp", "")
	assert.NoError(t, err)
	assert.Equal(t, 3, len(t4))
	assert.Equal(t, uint16(1433), t4[0].Port)
	assert.Equal(t, uint16(5432), t4[1].Port)
	assert.Equal(t, uint16(3306), t4[2].Port)

	// 5. Multi-protocol auto-port sweep
	t5, err := ResolveTargetPool("cs-main-wsl001", "", "", "ssh, mysql, postgresql, hana", "")
	assert.NoError(t, err)
	assert.Equal(t, 4, len(t5))
	assert.Equal(t, consts.SSH, t5[0].Protocol)
	assert.Equal(t, uint16(22), t5[0].Port)
	assert.Equal(t, consts.MYSQL, t5[1].Protocol)
	assert.Equal(t, uint16(3306), t5[1].Port)
	assert.Equal(t, consts.POSTGRES, t5[2].Protocol)
	assert.Equal(t, uint16(5432), t5[2].Port)
	assert.Equal(t, consts.SAPHANA, t5[3].Protocol)
	assert.Equal(t, uint16(30015), t5[3].Port)

	// 6. Cartesian matrix (2 hosts x 2 ports)
	t6, err := ResolveTargetPool("srv1, srv2", "80, 443", "", "http", "")
	assert.NoError(t, err)
	assert.Equal(t, 4, len(t6))
	assert.Equal(t, "srv1", t6[0].Host)
	assert.Equal(t, uint16(80), t6[0].Port)
	assert.Equal(t, "srv1", t6[1].Host)
	assert.Equal(t, uint16(443), t6[1].Port)
	assert.Equal(t, "srv2", t6[2].Host)
	assert.Equal(t, uint16(80), t6[2].Port)
	assert.Equal(t, "srv2", t6[3].Host)
	assert.Equal(t, uint16(443), t6[3].Port)

	// 7. Heterogeneous URIs with schemes
	t7, err := ResolveTargetPool("", "", "ssh://srv1:22, mysql://srv1:3306, https://srv2:8443", "", "")
	assert.NoError(t, err)
	assert.Equal(t, 3, len(t7))
	assert.Equal(t, consts.SSH, t7[0].Protocol)
	assert.Equal(t, uint16(22), t7[0].Port)
	assert.Equal(t, consts.MYSQL, t7[1].Protocol)
	assert.Equal(t, uint16(3306), t7[1].Port)
	assert.Equal(t, consts.HTTPS, t7[2].Protocol)
	assert.Equal(t, uint16(8443), t7[2].Port)

	// 8. Error when no targets are supplied
	_, err = ResolveTargetPool("", "", "", "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--host, --port, or --uri")
}


