package probers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/edsilegx/netping/pkg/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestCertBase64(t *testing.T, notAfter time.Time) string {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Microsoft Entra Test Signing Key",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(certBytes)
}

func TestEntra_PingSuccessWithJWKSAudit(t *testing.T) {
	certB64 := generateTestCertBase64(t, time.Now().Add(60*24*time.Hour))

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := entraJWKSResponse{
			Keys: []entraJWKKey{
				{
					Kty: "RSA",
					Use: "sig",
					Kid: "test-kid-1",
					Alg: "RS256",
					X5c: []string{certB64},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := entraOIDCConfig{
			Issuer:                           "https://login.microsoftonline.com/common/v2.0",
			AuthorizationEndpoint:            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenEndpoint:                    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			JWKSURI:                          jwksServer.URL + "/discovery/v2.0/keys",
			ScopesSupported:                  []string{"openid", "profile", "email", "offline_access"},
			IDTokenSigningAlgValuesSupported: []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(u.Port())

	pinger := BuildPinger(FactoryOptions{
		Protocol: consts.ENTRA,
		Hostname: u.Hostname(),
		Port:     uint16(port),
		URI:      ts.URL + "/common/v2.0/.well-known/openid-configuration",
		Timeout:  3 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Equal(t, http.StatusOK, res.HTTPStatus)
	assert.Contains(t, res.Diagnostics, "CloudEnv: Microsoft Entra ID (Azure Commercial)")
	assert.Contains(t, res.Diagnostics, "TokenPath: /common/oauth2/v2.0/token")
	assert.Contains(t, res.Diagnostics, "JWKS: 1 keys")
	assert.Contains(t, res.Diagnostics, "RS256")
	assert.Contains(t, res.Diagnostics, "openid")
}

func TestEntra_PingCriticalKeyExpiryAlert(t *testing.T) {
	// Certificate expiring in 5 days -> triggers critical alert
	criticalCertB64 := generateTestCertBase64(t, time.Now().Add(5*24*time.Hour))

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := entraJWKSResponse{
			Keys: []entraJWKKey{
				{
					Kty: "RSA",
					Use: "sig",
					Kid: "critical-key-01",
					Alg: "RS256",
					X5c: []string{criticalCertB64},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := entraOIDCConfig{
			Issuer:        "https://login.microsoftonline.us/organizations/v2.0",
			TokenEndpoint: "https://login.microsoftonline.us/organizations/oauth2/v2.0/token",
			JWKSURI:       jwksServer.URL + "/keys",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	port, _ := strconv.Atoi(u.Port())

	pinger := BuildPinger(FactoryOptions{
		Protocol: consts.ENTRA,
		Hostname: u.Hostname(),
		Port:     uint16(port),
		URI:      ts.URL + "/organizations/v2.0/.well-known/openid-configuration",
		Timeout:  3 * time.Second,
	})

	res := pinger.Ping(context.Background())
	assert.NoError(t, res.Err)
	assert.Contains(t, res.Diagnostics, "CloudEnv: Microsoft Entra ID (Azure US Government)")
	assert.Contains(t, res.Diagnostics, "CRITICAL ALERT: Key critical-key-01 expires")
}

func TestEntra_BuildTargetURL_Variations(t *testing.T) {
	// 1. Default target with empty URI
	p2 := NewEntraing(EntraOptions{
		Hostname: "login.microsoftonline.com",
		Port:     443,
	})
	url2, err2 := p2.buildTargetURL()
	assert.NoError(t, err2)
	assert.Equal(t, "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration", url2.String())

	// 2. Target URI with scheme and custom path
	p3 := NewEntraing(EntraOptions{
		URI: "https://login.microsoftonline.com/custom-tenant-guid/v2.0/.well-known/openid-configuration",
	})
	url3, err3 := p3.buildTargetURL()
	assert.NoError(t, err3)
	assert.Equal(t, "https://login.microsoftonline.com/custom-tenant-guid/v2.0/.well-known/openid-configuration", url3.String())

	// 3. Target URI without scheme
	p4 := NewEntraing(EntraOptions{
		URI: "login.microsoftonline.com/mytenant/v2.0/.well-known/openid-configuration",
	})
	url4, err4 := p4.buildTargetURL()
	assert.NoError(t, err4)
	assert.Equal(t, "https://login.microsoftonline.com/mytenant/v2.0/.well-known/openid-configuration", url4.String())

	// 4. Custom port 8443
	p5 := NewEntraing(EntraOptions{
		Hostname: "login.microsoftonline.com",
		Port:     8443,
	})
	url5, err5 := p5.buildTargetURL()
	assert.NoError(t, err5)
	assert.Equal(t, "https://login.microsoftonline.com:8443/common/v2.0/.well-known/openid-configuration", url5.String())
}

func TestEntra_Diagnostics_ChinaAndCustom(t *testing.T) {
	p := NewEntraing(EntraOptions{
		Hostname: "login.chinacloudapi.cn",
	})

	cfg := entraOIDCConfig{
		Issuer:                           "https://login.chinacloudapi.cn/common/v2.0",
		TokenEndpoint:                    "https://login.chinacloudapi.cn/common/oauth2/v2.0/token",
		ScopesSupported:                  []string{"openid", "profile"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}
	body, _ := json.Marshal(cfg)

	diag := p.parseDiagnostics(body, http.DefaultClient, context.Background(), nil)
	assert.Contains(t, diag, "CloudEnv: Microsoft Entra ID (Azure China 21Vianet)")
	assert.Contains(t, diag, "Scopes: [openid, profile]")
	assert.Contains(t, diag, "SigningAlgs: [RS256]")
}

func TestEntra_JWKS_Caching_And_Errors(t *testing.T) {
	p := NewEntraing(EntraOptions{
		Timeout: 2 * time.Second,
	})

	ctx := context.Background()

	// 1. Invalid JWKS URI returns empty string
	info1 := p.auditJWKS("http://127.0.0.1:1/invalid-jwks", http.DefaultClient, ctx)
	assert.Empty(t, info1)

	// 2. JWKS returning HTTP 500
	tsErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer tsErr.Close()

	info2 := p.auditJWKS(tsErr.URL, http.DefaultClient, ctx)
	assert.Empty(t, info2)

	// 3. JWKS returning malformed cert
	tsBadCert := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := entraJWKSResponse{
			Keys: []entraJWKKey{
				{
					Kid: "bad-cert-key",
					X5c: []string{"!!!NOT-BASE64!!!"},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer tsBadCert.Close()

	info3 := p.auditJWKS(tsBadCert.URL, http.DefaultClient, ctx)
	assert.Contains(t, info3, "JWKS: 1")

	// 4. JWKS cache hit
	cachedInfo := p.auditJWKS(tsBadCert.URL, http.DefaultClient, ctx)
	assert.Equal(t, info3, cachedInfo)
}

func TestEntra_Network_And_Status_Errors(t *testing.T) {
	// 1. Connection error
	p1 := NewEntraing(EntraOptions{
		Hostname: "127.0.0.1",
		Port:     1,
		Timeout:  100 * time.Millisecond,
	})
	res1 := p1.Ping(context.Background())
	assert.Error(t, res1.Err)

	// 2. Server 500
	ts500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts500.Close()

	p2 := NewEntraing(EntraOptions{
		URI:     ts500.URL,
		Timeout: 1 * time.Second,
	})
	res2 := p2.Ping(context.Background())
	assert.Error(t, res2.Err)
	assert.Contains(t, res2.Err.Error(), "500")
}
